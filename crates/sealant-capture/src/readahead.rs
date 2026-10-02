//! Parallel read-ahead for a build that nothing competes with.
//!
//! A build reads its files one at a time: stat, read, chunk, hash, compress, stat. A final flush
//! runs after every writer stopped, with a Stop waiting on it, so keeping that to one core only
//! makes the Stop wait (2026-10-02: 69 s to read a 106,628-file `node_modules`). Worker threads
//! read the files the build is about to ask for, in the order it will ask, and the build takes
//! each result as it reaches the file.
//!
//! What a worker read is what the build's own read would be: the same stat before and after the
//! same chunking. A read that failed, or whose file changed underneath, is dropped, and the build
//! reads that file itself, with its retries and its errors.
//!
//! Bounded: workers start no new file while [`BUDGET_BYTES`] of results wait, and a file over
//! [`MAX_FILE_BYTES`] is never read ahead (the build streams it). The build never waits on a file
//! no worker started: it reads that file itself. So a wrong guess at the order costs speed, never
//! progress.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};

use crate::chunk::{ChunkId, chunk_file};
use crate::index::{FileStat, now_ns};
use crate::longpath;
use crate::pack::compress_chunk;

/// Compressed results that may wait for the build before workers stop starting files.
const BUDGET_BYTES: usize = 128 << 20;

/// The largest file read ahead: a worker holds a whole file's compressed chunks.
pub(crate) const MAX_FILE_BYTES: u64 = 16 << 20;

/// One chunk as a worker read it: hashed and compressed.
#[derive(Debug)]
pub(crate) struct PackedChunk {
    pub(crate) id: ChunkId,
    /// Uncompressed length.
    pub(crate) size: u64,
    pub(crate) packed: Vec<u8>,
}

/// One file read ahead whole: its stat was the same before and after the read.
#[derive(Debug)]
pub(crate) struct ReadAheadFile {
    /// When the read began (the build's racy-read check).
    pub(crate) started: i128,
    pub(crate) stat: FileStat,
    pub(crate) chunks: Vec<PackedChunk>,
    pub(crate) bytes: u64,
}

#[derive(Debug)]
enum Slot {
    Queued,
    Reading,
    /// The read (`None`: it failed or the file changed), and the bytes it holds of the budget.
    Done(Option<ReadAheadFile>, usize),
    /// The build read it itself.
    Taken,
}

#[derive(Debug, Default)]
struct State {
    slots: HashMap<PathBuf, Slot>,
    queue: VecDeque<PathBuf>,
    held: usize,
    stop: bool,
}

type Shared = Arc<(Mutex<State>, Condvar)>;

fn lock(shared: &Shared) -> MutexGuard<'_, State> {
    shared.0.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Worker threads reading a build's files ahead of it. Dropping it stops and joins them.
#[derive(Debug)]
pub(crate) struct ReadAhead {
    shared: Shared,
    workers: Vec<JoinHandle<()>>,
}

impl ReadAhead {
    /// Read `files` ahead, in order, on `workers` threads.
    pub(crate) fn start(files: Vec<PathBuf>, workers: usize) -> Self {
        let mut state = State::default();
        for file in files {
            if !state.slots.contains_key(&file) {
                state.slots.insert(file.clone(), Slot::Queued);
                state.queue.push_back(file);
            }
        }
        let shared: Shared = Arc::new((Mutex::new(state), Condvar::new()));
        let workers = (0..workers)
            .filter_map(|n| {
                let shared = Arc::clone(&shared);
                thread::Builder::new()
                    .name(format!("capture-read-{n}"))
                    .spawn(move || work(&shared))
                    .ok()
            })
            .collect();
        Self { shared, workers }
    }

    /// The read of `abs`, once: `None` when it was not planned, no worker started it (the build
    /// reads it now), or the worker's read did not hold. Waits for a read in progress.
    pub(crate) fn take(&self, abs: &Path) -> Option<ReadAheadFile> {
        let mut state = lock(&self.shared);
        loop {
            match state.slots.get(abs) {
                None | Some(Slot::Taken) => return None,
                Some(Slot::Queued) => {
                    state.slots.insert(abs.to_path_buf(), Slot::Taken);
                    return None;
                }
                Some(Slot::Reading) => {
                    state = self
                        .shared
                        .1
                        .wait(state)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                Some(Slot::Done(..)) => {
                    let Some(Slot::Done(file, held)) = state.slots.remove(abs) else {
                        return None;
                    };
                    state.held = state.held.saturating_sub(held);
                    self.shared.1.notify_all();
                    return file;
                }
            }
        }
    }
}

impl Drop for ReadAhead {
    fn drop(&mut self) {
        lock(&self.shared).stop = true;
        self.shared.1.notify_all();
        for worker in self.workers.drain(..) {
            worker.join().ok();
        }
    }
}

fn work(shared: &Shared) {
    loop {
        let abs = {
            let mut state = lock(shared);
            loop {
                if state.stop {
                    return;
                }
                if state.held < BUDGET_BYTES {
                    // The next file the build has not read itself.
                    let next = loop {
                        match state.queue.pop_front() {
                            None => break None,
                            Some(file) if matches!(state.slots.get(&file), Some(Slot::Queued)) => {
                                break Some(file);
                            }
                            Some(_) => {}
                        }
                    };
                    let Some(file) = next else { return };
                    state.slots.insert(file.clone(), Slot::Reading);
                    break file;
                }
                state = shared.1.wait(state).unwrap_or_else(PoisonError::into_inner);
            }
        };
        // A panic here must not leave the build waiting on a read that never ends.
        let read = catch_unwind(AssertUnwindSafe(|| read_whole(&abs).ok().flatten()))
            .ok()
            .flatten();
        let held = read
            .as_ref()
            .map_or(0, |file| file.chunks.iter().map(|c| c.packed.len()).sum());
        let mut state = lock(shared);
        state.slots.insert(abs, Slot::Done(read, held));
        state.held += held;
        shared.1.notify_all();
    }
}

/// One read of `abs`, as the build makes it: `None` when the file changed underneath.
fn read_whole(abs: &Path) -> io::Result<Option<ReadAheadFile>> {
    let started = now_ns();
    let before = FileStat::of(&longpath::symlink_metadata(abs)?);
    let file = longpath::open(abs)?;
    let mut chunks = Vec::new();
    let mut bytes = 0u64;
    for chunk in chunk_file(file)? {
        let chunk = chunk?;
        let size = chunk.data.len() as u64;
        bytes += size;
        chunks.push(PackedChunk {
            id: chunk.id,
            size,
            packed: compress_chunk(&chunk.data)?,
        });
    }
    let after = FileStat::of(&longpath::symlink_metadata(abs)?);
    Ok((before == after).then_some(ReadAheadFile {
        started,
        stat: after,
        chunks,
        bytes,
    }))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::chunk::chunk_bytes;

    #[test]
    fn reads_each_planned_file_once_as_the_build_would() {
        let dir = tempfile::tempdir().unwrap();
        let mut files = Vec::new();
        for n in 0..40 {
            let path = dir.path().join(format!("f{n}"));
            fs::write(&path, format!("contents of file {n}\n").repeat(n + 1)).unwrap();
            files.push(path);
        }
        let ahead = ReadAhead::start(files.clone(), 4);
        for (n, path) in files.iter().enumerate() {
            let text = format!("contents of file {n}\n").repeat(n + 1);
            // Read by a worker, or (no worker had started it) left to the build.
            if let Some(read) = ahead.take(path) {
                let want: Vec<ChunkId> =
                    chunk_bytes(text.as_bytes()).iter().map(|c| c.id).collect();
                assert_eq!(read.chunks.iter().map(|c| c.id).collect::<Vec<_>>(), want);
                assert_eq!(read.bytes, text.len() as u64);
                assert_eq!(
                    read.stat,
                    FileStat::of(&fs::symlink_metadata(path).unwrap())
                );
            }
            assert!(ahead.take(path).is_none(), "a read is handed out once");
        }
    }

    #[test]
    fn a_file_nobody_planned_or_that_cannot_be_read_is_the_builds_own() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let ahead = ReadAhead::start(vec![missing.clone()], 2);
        assert!(ahead.take(&dir.path().join("unplanned")).is_none());
        assert!(ahead.take(&missing).is_none());
    }

    #[test]
    fn unread_results_never_stall_the_build() {
        // More results than the budget holds, taken in the reverse of the planned order: the
        // build reads what no worker started and waits only for reads in progress.
        let dir = tempfile::tempdir().unwrap();
        let mut files = Vec::new();
        for n in 0..64 {
            let path = dir.path().join(format!("f{n}"));
            fs::write(&path, vec![u8::try_from(n).unwrap(); 4096]).unwrap();
            files.push(path);
        }
        let ahead = ReadAhead::start(files.clone(), 3);
        for path in files.iter().rev() {
            let _ = ahead.take(path);
        }
    }
}
