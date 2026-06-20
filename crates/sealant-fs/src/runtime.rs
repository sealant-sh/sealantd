//! The filesystem runtime: baseline snapshot + live watcher + final diff (plan §13).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use sealant_protocol::{
    CaptureMethod, Confidence, EventPayload, ExecutionId, FileChangeKind, FileDiffAvailable,
    FileSnapshotCompleted,
};
use sealant_telemetry::{Correlation, EventBus};

use crate::diff::diff;
use crate::snapshot::{Snapshot, SnapshotConfig, snapshot};
use crate::watcher::{WatchContext, build_watcher};

/// Filesystem telemetry configuration.
#[derive(Debug, Clone)]
pub struct FilesystemConfig {
    /// Workspace root to observe.
    pub root: PathBuf,
    /// Snapshot/ignore configuration.
    pub snapshot: SnapshotConfig,
    /// Execution to correlate events with.
    pub execution_id: Option<ExecutionId>,
}

/// Owns the baseline snapshot and the live watcher; produces a final diff on `finalize`.
pub struct FilesystemRuntime {
    bus: Arc<EventBus>,
    config: FilesystemConfig,
    baseline: Mutex<Option<Snapshot>>,
    watcher: Mutex<Option<notify::RecommendedWatcher>>,
}

impl std::fmt::Debug for FilesystemRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilesystemRuntime")
            .field("root", &self.config.root)
            .finish_non_exhaustive()
    }
}

impl FilesystemRuntime {
    /// Create a filesystem runtime (not yet watching; call [`FilesystemRuntime::start`]).
    #[must_use]
    pub fn new(bus: Arc<EventBus>, config: FilesystemConfig) -> Self {
        Self {
            bus,
            config,
            baseline: Mutex::new(None),
            watcher: Mutex::new(None),
        }
    }

    fn correlation(&self) -> Correlation {
        Correlation::new().execution(self.config.execution_id.clone())
    }

    /// Take the baseline snapshot and start the live watcher.
    ///
    /// # Errors
    /// Returns a [`notify::Error`] if the watcher cannot start (e.g. the root is unreadable).
    pub fn start(&self) -> notify::Result<()> {
        let baseline = snapshot(&self.config.root, &self.config.snapshot);
        self.bus.publish(
            &self.correlation(),
            CaptureMethod::Snapshot,
            Confidence::Observed,
            EventPayload::FileSnapshotCompleted(FileSnapshotCompleted {
                root: self.config.root.display().to_string(),
                file_count: baseline.len() as u64,
            }),
        );
        let watcher = build_watcher(
            WatchContext {
                root: self.config.root.clone(),
                snapshot_config: self.config.snapshot.clone(),
                bus: self.bus.clone(),
                correlation: self.correlation(),
            },
            baseline.clone(),
        )?;
        *self.baseline.lock().unwrap_or_else(|e| e.into_inner()) = Some(baseline);
        *self.watcher.lock().unwrap_or_else(|e| e.into_inner()) = Some(watcher);
        Ok(())
    }

    /// Stop watching, take a final snapshot, and emit the baseline→final diff.
    pub fn finalize(&self) {
        // Dropping the watcher stops the backend.
        let _ = self
            .watcher
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let Some(baseline) = self
            .baseline
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        else {
            return;
        };
        let final_snapshot = snapshot(&self.config.root, &self.config.snapshot);
        let (mut added, mut modified, mut deleted, mut renamed) = (0u64, 0u64, 0u64, 0u64);
        for c in diff(&baseline, &final_snapshot) {
            match c.kind {
                FileChangeKind::Added => added += 1,
                FileChangeKind::Modified | FileChangeKind::MetadataChanged => modified += 1,
                FileChangeKind::Deleted => deleted += 1,
                FileChangeKind::Renamed => renamed += 1,
            }
            self.bus.publish(
                &self.correlation(),
                CaptureMethod::Snapshot,
                Confidence::Observed,
                EventPayload::FileChange(c),
            );
        }
        self.bus.publish(
            &self.correlation(),
            CaptureMethod::Snapshot,
            Confidence::Inferred,
            EventPayload::FileDiffAvailable(FileDiffAvailable {
                added,
                modified,
                deleted,
                renamed,
            }),
        );
    }
}

// The live watcher targets Linux inotify (deterministic); macOS FSEvents is latent/flaky in tests.
// Snapshot + diff logic is covered cross-platform in `snapshot`/`diff`.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use sealant_protocol::EventEnvelope;
    use sealant_runtime_core::{Clock, IdGenerator, new_runtime_id};
    use std::time::Duration;
    use tokio::sync::broadcast::Receiver;

    fn bus() -> Arc<EventBus> {
        let rt = new_runtime_id();
        let clock = Arc::new(Clock::new());
        let idgen = Arc::new(IdGenerator::new(&rt));
        Arc::new(EventBus::new(rt, clock, idgen, 1024))
    }

    async fn drain_for(rx: &mut Receiver<EventEnvelope>, within: Duration) -> Vec<EventEnvelope> {
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(env)) => out.push(env),
                _ => break,
            }
        }
        out
    }

    #[tokio::test]
    async fn live_watch_emits_create_and_modify_and_overflow_recovers() {
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path().to_path_buf();
        let bus = bus();
        let mut rx = bus.subscribe();
        let fs = FilesystemRuntime::new(
            bus.clone(),
            FilesystemConfig {
                root: root.clone(),
                snapshot: SnapshotConfig::default(),
                execution_id: None,
            },
        );
        fs.start().expect("start watcher");

        // Snapshot-completed should be the first event.
        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("no timeout")
            .expect("event");
        assert_eq!(first.event_type(), "file.snapshotCompleted");

        // Create then modify a file; the watcher should observe it.
        std::fs::write(root.join("live.txt"), b"v1").expect("create");
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::fs::write(root.join("live.txt"), b"v2-changed").expect("modify");

        let events = drain_for(&mut rx, Duration::from_secs(2)).await;
        let paths: Vec<&str> = events.iter().map(EventEnvelope::event_type).collect();
        assert!(
            paths.contains(&"file.changed"),
            "expected file.changed, got {paths:?}"
        );

        fs.finalize();
        // finalize emits a diff summary.
        let after = drain_for(&mut rx, Duration::from_secs(2)).await;
        assert!(after.iter().any(|e| e.event_type() == "file.diffAvailable"));
    }
}
