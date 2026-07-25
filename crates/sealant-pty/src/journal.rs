//! Durable per-session PTY output journals.
//!
//! The journal is the product read surface for interactive sessions: reattach-after-disconnect and
//! scrollback replay both read from it, so every output chunk is appended here (post-redaction)
//! before any live fan-out. Records carry contiguous monotonic sequence numbers starting at 0 and
//! a CRC32, and live in at most two size-bounded segment files (`current` + `previous`): when the
//! current segment fills, it becomes the previous segment and the oldest is deleted, so per-session
//! disk is bounded at twice the segment cap while replays keep a deep, contiguous tail.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// One replayable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalChunk {
    /// Journal sequence of this record.
    pub sequence: u64,
    /// Record payload (redacted output bytes).
    pub data: Vec<u8>,
}

/// Fixed per-record header: sequence (u64 BE) + payload length (u32 BE); a CRC32 (BE) of both plus
/// the payload trails the record.
const HEADER_BYTES: u64 = 8 + 4;
const TRAILER_BYTES: u64 = 4;

fn record_len(payload: usize) -> u64 {
    HEADER_BYTES + payload as u64 + TRAILER_BYTES
}

/// One append-only segment file plus its in-memory record index.
#[derive(Debug)]
struct Segment {
    path: PathBuf,
    file: File,
    /// Sequence of the first record in this segment.
    first_seq: u64,
    /// Byte offset of each record, indexed by (seq - first_seq).
    offsets: Vec<u64>,
    /// Total bytes written.
    bytes: u64,
}

impl Segment {
    fn create(path: PathBuf, first_seq: u64) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        Ok(Self {
            path,
            file,
            first_seq,
            offsets: Vec::new(),
            bytes: 0,
        })
    }

    fn append(&mut self, seq: u64, payload: &[u8]) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(record_len(payload.len()) as usize);
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&buf);
        buf.extend_from_slice(&hasher.finalize().to_be_bytes());
        self.file.write_all(&buf)?;
        self.offsets.push(self.bytes);
        self.bytes += buf.len() as u64;
        Ok(())
    }

    /// Next sequence after the records in this segment.
    fn end_seq(&self) -> u64 {
        self.first_seq + self.offsets.len() as u64
    }

    /// Read records `[from, end_seq)` up to `max_bytes` of payload, via an independent read handle
    /// (the write handle keeps appending).
    fn read_from(&self, from: u64, max_bytes: u64, out: &mut Vec<JournalChunk>) -> u64 {
        if from >= self.end_seq() || max_bytes == 0 {
            return 0;
        }
        let start = from.max(self.first_seq);
        let Some(&offset) = self.offsets.get((start - self.first_seq) as usize) else {
            return 0;
        };
        let Ok(mut reader) = File::open(&self.path) else {
            return 0;
        };
        if reader.seek(SeekFrom::Start(offset)).is_err() {
            return 0;
        }
        let mut consumed = 0u64;
        let mut seq = start;
        while seq < self.end_seq() && consumed < max_bytes {
            let mut header = [0u8; HEADER_BYTES as usize];
            if reader.read_exact(&mut header).is_err() {
                break;
            }
            let rec_seq = u64::from_be_bytes(header[0..8].try_into().unwrap_or_default());
            let len = u32::from_be_bytes(header[8..12].try_into().unwrap_or_default()) as usize;
            let mut payload = vec![0u8; len];
            let mut trailer = [0u8; TRAILER_BYTES as usize];
            if reader.read_exact(&mut payload).is_err() || reader.read_exact(&mut trailer).is_err()
            {
                break;
            }
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(&header);
            hasher.update(&payload);
            let crc_ok = hasher.finalize().to_be_bytes() == trailer;
            if rec_seq != seq || !crc_ok {
                tracing::warn!(
                    segment = %self.path.display(),
                    expected = seq,
                    got = rec_seq,
                    crc_ok,
                    "journal record mismatch; truncating replay"
                );
                break;
            }
            consumed += payload.len() as u64;
            out.push(JournalChunk {
                sequence: seq,
                data: payload,
            });
            seq += 1;
        }
        consumed
    }
}

/// A per-session durable output journal: two rotating segments plus monotonic sequencing.
#[derive(Debug)]
pub struct SessionJournal {
    dir: PathBuf,
    session: String,
    generation: u64,
    previous: Option<Segment>,
    current: Segment,
    segment_limit: u64,
}

impl SessionJournal {
    /// Create a fresh journal for `session` under `dir` (created if absent).
    ///
    /// # Errors
    /// Returns an I/O error if the directory or first segment cannot be created.
    pub fn create(dir: &Path, session: &str, segment_limit: u64) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let current = Segment::create(segment_path(dir, session, 0), 0)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            session: session.to_owned(),
            generation: 0,
            previous: None,
            current,
            segment_limit: segment_limit.max(64 * 1024),
        })
    }

    /// Append one output chunk, returning its journal sequence.
    ///
    /// # Errors
    /// Returns an I/O error if the write fails (the sequence is not consumed).
    pub fn append(&mut self, payload: &[u8]) -> std::io::Result<u64> {
        if self.current.bytes > 0
            && self.current.bytes + record_len(payload.len()) > self.segment_limit
        {
            self.rotate()?;
        }
        let seq = self.current.end_seq();
        self.current.append(seq, payload)?;
        Ok(seq)
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.generation += 1;
        let next = Segment::create(
            segment_path(&self.dir, &self.session, self.generation),
            self.current.end_seq(),
        )?;
        let retired = std::mem::replace(&mut self.current, next);
        if let Some(old) = self.previous.replace(retired) {
            let _ = std::fs::remove_file(&old.path);
        }
        Ok(())
    }

    /// First sequence still retained (0 until the first rotation drops a segment).
    #[must_use]
    pub fn first_seq(&self) -> u64 {
        self.previous
            .as_ref()
            .map_or(self.current.first_seq, |p| p.first_seq)
    }

    /// The next sequence to be assigned (i.e. the current end cursor).
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.current.end_seq()
    }

    /// Read records from `from` (clamped to [`SessionJournal::first_seq`]) until `max_bytes` of
    /// payload or the journal end. Returns the records in order.
    #[must_use]
    pub fn read_from(&self, from: u64, max_bytes: u64) -> Vec<JournalChunk> {
        let from = from.max(self.first_seq());
        let mut out = Vec::new();
        let mut budget = max_bytes;
        if let Some(prev) = &self.previous {
            budget = budget.saturating_sub(prev.read_from(from, budget, &mut out));
        }
        let resume = out.last().map_or(from, |c| c.sequence + 1);
        self.current.read_from(resume, budget, &mut out);
        out
    }

    /// Remove the journal's segment files (called when a finished session is evicted).
    pub fn remove_files(&self) {
        if let Some(prev) = &self.previous {
            let _ = std::fs::remove_file(&prev.path);
        }
        let _ = std::fs::remove_file(&self.current.path);
    }
}

fn segment_path(dir: &Path, session: &str, generation: u64) -> PathBuf {
    dir.join(format!("{session}.{generation:06}.journal"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal(limit: u64) -> (tempfile::TempDir, SessionJournal) {
        let dir = tempfile::tempdir().expect("tmp");
        let j = SessionJournal::create(dir.path(), "ses_test", limit).expect("create");
        (dir, j)
    }

    #[test]
    fn appends_are_contiguous_and_replayable_from_zero() {
        let (_dir, mut j) = journal(1 << 20);
        for i in 0..10u32 {
            let seq = j.append(format!("chunk-{i}\n").as_bytes()).expect("append");
            assert_eq!(seq, u64::from(i));
        }
        let chunks = j.read_from(0, u64::MAX);
        assert_eq!(chunks.len(), 10);
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(c.sequence, i as u64);
            assert_eq!(c.data, format!("chunk-{i}\n").as_bytes());
        }
        assert_eq!(j.next_seq(), 10);
        assert_eq!(j.first_seq(), 0);
    }

    #[test]
    fn read_from_middle_and_bounded_by_max_bytes() {
        let (_dir, mut j) = journal(1 << 20);
        for i in 0..20u32 {
            j.append(format!("{i:04}").as_bytes()).expect("append");
        }
        let tail = j.read_from(15, u64::MAX);
        assert_eq!(tail.first().map(|c| c.sequence), Some(15));
        assert_eq!(tail.len(), 5);
        // 4-byte payloads: an 10-byte budget yields 3 records (budget check is pre-read).
        let bounded = j.read_from(0, 10);
        assert!(
            bounded.len() >= 2 && bounded.len() <= 3,
            "{}",
            bounded.len()
        );
    }

    #[test]
    fn rotation_bounds_disk_and_keeps_contiguous_tail() {
        // Tiny segments force rotation. The floor is 64 KiB, so write big payloads.
        let (dir, mut j) = journal(1);
        let payload = vec![b'x'; 40 * 1024];
        for _ in 0..6 {
            j.append(&payload).expect("append");
        }
        // Segment floor 64 KiB fits one 40 KiB record per segment → rotations happened.
        assert!(j.first_seq() > 0, "oldest segment should have been dropped");
        let files: Vec<_> = std::fs::read_dir(dir.path())
            .expect("readdir")
            .flatten()
            .collect();
        assert!(
            files.len() <= 2,
            "at most two segment files, got {}",
            files.len()
        );
        // The retained tail is contiguous up to next_seq.
        let chunks = j.read_from(0, u64::MAX);
        let first = j.first_seq();
        assert_eq!(chunks.first().map(|c| c.sequence), Some(first));
        assert_eq!(
            chunks.last().map(|c| c.sequence),
            Some(j.next_seq() - 1),
            "tail must reach the end cursor"
        );
        for w in chunks.windows(2) {
            assert_eq!(w[1].sequence, w[0].sequence + 1, "gap in retained tail");
        }
    }

    #[test]
    fn binary_payloads_round_trip() {
        let (_dir, mut j) = journal(1 << 20);
        let payload = [0x00u8, 0xff, 0x1b, b'[', b'3', b'1', b'm'];
        j.append(&payload).expect("append");
        let chunks = j.read_from(0, u64::MAX);
        assert_eq!(chunks[0].data, payload);
    }

    #[test]
    fn remove_files_deletes_segments() {
        let (dir, mut j) = journal(1 << 20);
        j.append(b"data").expect("append");
        j.remove_files();
        let files: Vec<_> = std::fs::read_dir(dir.path())
            .expect("readdir")
            .flatten()
            .collect();
        assert!(files.is_empty());
    }
}
