//! No process is alive when a final flush seals (review 2026-09-28, sixth pass, #1). The
//! flush's quiesce stopped every writer, but anything started after it — a process a git of the
//! capture's ran, one that entered the workspace from outside — kept writing past the seal, and
//! the sealed head was not the disk. The flush now takes a census before it seals: a process it
//! finds is killed, the classes are snapped again, and the seal waits for a census that finds
//! none.
//!
//! Here the store starts the late writer: its first PUT after the writers stopped spawns a
//! process (a descendant of the daemon, as a capture's git child would be) that writes the
//! victim half a second later, after the flush would have answered.
//!
//! One test in its own binary on purpose: the sweep takes every descendant of the process it
//! runs in, as the daemon's does, and other tests' processes would be its descendants too.

mod support;

use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use sealant_capture::BlobSink;
use sealant_capture::sink::{BlobSource, PutOutcome, SinkError};
use sealantd::Runtime;
use support::{EXECUTOR, boot, restore, start};

/// A store that, once the runtime stopped every writer, starts one more with its next PUT.
struct SpawnsAfterQuiesce {
    inner: Arc<dyn BlobSink>,
    runtime: Arc<OnceLock<Arc<Runtime>>>,
    spawned: AtomicBool,
    victim: PathBuf,
    /// The writer, waited for by the test.
    child: Arc<Mutex<Option<Child>>>,
}

impl SpawnsAfterQuiesce {
    fn touch(&self) {
        let stopped = self.runtime.get().is_some_and(|rt| rt.writers_stopped());
        if stopped && !self.spawned.swap(true, Ordering::SeqCst) {
            let child = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "sleep 0.5; printf 'written after the seal\\n' > '{}'",
                    self.victim.display()
                ))
                .spawn()
                .unwrap();
            *self.child.lock().unwrap() = Some(child);
        }
    }
}

impl BlobSink for SpawnsAfterQuiesce {
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
async fn a_process_alive_at_the_seal_is_stopped_before_the_seal() {
    let tmp = tempfile::tempdir().unwrap();
    let slot: Arc<OnceLock<Arc<Runtime>>> = Arc::new(OnceLock::new());
    let victim = tmp.path().join("ws/src/lib.rs");
    let sink_slot = Arc::clone(&slot);
    let child: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
    let sink_child = Arc::clone(&child);
    let (boot, registrar) = boot(tmp.path(), move |inner| {
        Arc::new(SpawnsAfterQuiesce {
            inner,
            runtime: sink_slot,
            spawned: AtomicBool::new(false),
            victim,
            child: sink_child,
        })
    });
    let ws = tmp.path().join("ws");
    std::fs::write(ws.join("src/lib.rs"), b"pub fn f() { edited() }\n").unwrap();

    let runtime = start(&ws, boot);
    assert!(slot.set(runtime.clone()).is_ok());
    let report = runtime.final_flush(None, Some(50)).await.unwrap();
    // Long enough for a writer that was left running to have written.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let writer = child.lock().unwrap().take();
    assert!(writer.is_some(), "the store started the late writer");
    writer.unwrap().wait().unwrap();

    assert_eq!(
        std::fs::read(ws.join("src/lib.rs")).unwrap(),
        b"pub fn f() { edited() }\n",
        "a process alive at the seal wrote after it"
    );
    assert!(report.complete, "{report:?}");
    let head = registrar.head().unwrap();
    assert!(
        head.manifest
            .final_seal
            .as_ref()
            .is_some_and(|seal| seal.executor == EXECUTOR),
        "the complete flush sealed its head"
    );
    let fresh = restore(tmp.path(), &registrar, "fresh");
    assert_eq!(
        std::fs::read(fresh.join("src/lib.rs")).unwrap(),
        std::fs::read(ws.join("src/lib.rs")).unwrap(),
        "the sealed head is the disk"
    );
}
