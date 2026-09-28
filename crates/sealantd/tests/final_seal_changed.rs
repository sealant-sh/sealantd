//! A seal is written only over the disk as it is (review 2026-09-28, fifth pass, #2; decision
//! 15): a change after a final flush's snaps and before its seal — here a write that lands while
//! the flush ships — left the flush sealing captures that no longer held the disk, before the
//! report said `changed`. The flush now settles the watcher and checks, before it seals, that
//! nothing changed since its snaps; it snaps again when something did, and seals only the
//! round that held still.
//!
//! One test in its own binary on purpose: the sweep takes every descendant of the process it
//! runs in, as the daemon's does, and other tests' processes would be its descendants too.

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sealant_capture::BlobSink;
use sealant_capture::sink::{BlobSource, PutOutcome, SinkError};
use support::{EXECUTOR, boot, final_flush, restore};

/// A store that, once armed, writes `path` on the disk with its first PUT: a change the
/// flush's snaps never read, made while it ships.
struct WritesOnPut {
    inner: Arc<dyn BlobSink>,
    armed: Arc<AtomicBool>,
    path: PathBuf,
}

impl WritesOnPut {
    fn touch(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            std::fs::write(&self.path, b"written while the final flush shipped\n").unwrap();
        }
    }
}

impl BlobSink for WritesOnPut {
    fn put_if_absent(&self, key: &str, source: BlobSource<'_>) -> Result<PutOutcome, SinkError> {
        self.touch();
        self.inner.put_if_absent(key, source)
    }
    fn put_multipart(
        &self,
        key: &str,
        file: &Path,
        part_size: u64,
        parts_in_flight: usize,
    ) -> Result<PutOutcome, SinkError> {
        self.touch();
        self.inner
            .put_multipart(key, file, part_size, parts_in_flight)
    }
    fn get(&self, key: &str) -> Result<Vec<u8>, SinkError> {
        self.inner.get(key)
    }
    fn exists(&self, key: &str) -> Result<bool, SinkError> {
        self.inner.exists(key)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_after_the_final_snaps_is_captured_before_the_seal() {
    let tmp = tempfile::tempdir().unwrap();
    let armed = Arc::new(AtomicBool::new(false));
    let victim = tmp.path().join("ws/src/lib.rs");
    let arm = Arc::clone(&armed);
    let (boot, registrar) = boot(tmp.path(), move |inner| {
        Arc::new(WritesOnPut {
            inner,
            armed: arm,
            path: victim,
        })
    });
    let ws = tmp.path().join("ws");
    std::fs::write(ws.join("src/lib.rs"), b"pub fn f() { edited() }\n").unwrap();
    armed.store(true, Ordering::SeqCst);

    let report = final_flush(&ws, boot).await;
    assert!(!armed.load(Ordering::SeqCst), "the write happened");
    assert_eq!(
        std::fs::read(ws.join("src/lib.rs")).unwrap(),
        b"written while the final flush shipped\n"
    );
    let head = registrar.head().unwrap();
    let sealed = head
        .manifest
        .final_seal
        .as_ref()
        .is_some_and(|seal| seal.executor == EXECUTOR);
    // A seal on the head says the head is the disk: whatever the report, it must be.
    if sealed {
        let fresh = restore(tmp.path(), &registrar, "fresh");
        assert_eq!(
            std::fs::read(fresh.join("src/lib.rs")).unwrap(),
            b"written while the final flush shipped\n",
            "a sealed head that is not the disk"
        );
    }
    // Snapped again, the round that held still is sealed: complete, and current.
    assert!(report.complete, "{report:?}");
    assert!(sealed, "the complete flush sealed its head");
}
