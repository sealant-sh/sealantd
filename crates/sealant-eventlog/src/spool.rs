//! The durable spool: rotating segment files with crash recovery, ack-based deletion, and a
//! disk-usage bound.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::record::{self, Record, RecordError, encoded_len};

/// When to fsync the active segment. `Interval` flushing is driven by the caller via [`Spool::flush`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsyncPolicy {
    /// fsync after every append (durable, slower).
    Always,
    /// Never fsync explicitly; rely on the caller's [`Spool::flush`] and the OS.
    Never,
}

/// Spool configuration.
#[derive(Debug, Clone)]
pub struct SpoolConfig {
    /// Spool directory.
    pub dir: PathBuf,
    /// Target maximum size of a single segment before rotating.
    pub segment_bytes: u64,
    /// Maximum total bytes across all segments before the oldest are evicted.
    pub disk_limit_bytes: u64,
    /// Maximum payload size of a single record.
    pub max_payload_bytes: u32,
    /// fsync policy.
    pub fsync: FsyncPolicy,
}

/// Outcome of replaying the spool on startup.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplayStats {
    /// Number of whole, valid records replayed.
    pub records: u64,
    /// Number of segments that ended in a corrupt record (non-tail loss).
    pub corrupt_segments: u64,
    /// Whether the final segment ended in a truncated (partial) record.
    pub truncated_tail: bool,
}

/// Spool errors.
#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    /// A payload exceeded the configured maximum record size.
    #[error("record payload length {len} exceeds maximum {max}")]
    PayloadTooLarge {
        /// Payload length.
        len: u32,
        /// Configured maximum.
        max: u32,
    },
    /// A single record is larger than the entire disk budget.
    #[error("record size {size} exceeds disk limit {limit}")]
    RecordExceedsDiskLimit {
        /// Encoded record size.
        size: u64,
        /// Disk limit.
        limit: u64,
    },
    /// An underlying I/O error.
    #[error(transparent)]
    Io(io::Error),
}

impl From<io::Error> for SpoolError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug)]
struct Segment {
    index: u64,
    path: PathBuf,
    max_sequence: u64,
    records: u64,
    bytes: u64,
}

/// An append-only, segmented, crash-recoverable spool.
#[derive(Debug)]
pub struct Spool {
    config: SpoolConfig,
    segments: Vec<Segment>,
    active: Option<File>,
    next_index: u64,
    total_bytes: u64,
    corrupt_segments: u64,
    truncated_tail: bool,
}

fn segment_name(index: u64) -> String {
    format!("seg-{index:020}.log")
}

fn parse_segment_index(name: &str) -> Option<u64> {
    name.strip_prefix("seg-")?
        .strip_suffix(".log")?
        .parse()
        .ok()
}

/// The suffix of a segment being rewritten ([`Spool::rewrite`]): `seg-….log.rewrite`. Never read as
/// a segment; one left by a crash mid-rewrite is removed on open.
const REWRITE_SUFFIX: &str = ".rewrite";

fn is_stale_rewrite(name: &str) -> bool {
    name.strip_suffix(REWRITE_SUFFIX)
        .is_some_and(|segment| parse_segment_index(segment).is_some())
}

/// Read every whole record of a segment, stopping at the first that is not (as replay does).
fn read_segment(path: &Path, max_payload_bytes: u32) -> io::Result<Vec<Record>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut records = Vec::new();
    while let Ok(Some(rec)) = record::read_record(&mut reader, max_payload_bytes) {
        records.push(rec);
    }
    Ok(records)
}

/// fsync a directory, so a rename inside it survives a crash.
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

struct ScanResult {
    max_sequence: u64,
    records: u64,
    valid_bytes: u64,
    corrupt: bool,
    truncated: bool,
}

/// Scan a segment, healing it by truncating any partial/corrupt tail so only whole records remain.
fn scan_and_heal(path: &Path, max_payload_bytes: u32) -> io::Result<ScanResult> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let read_handle = file.try_clone()?;
    let mut reader = BufReader::new(read_handle);
    let mut result = ScanResult {
        max_sequence: 0,
        records: 0,
        valid_bytes: 0,
        corrupt: false,
        truncated: false,
    };
    loop {
        match record::read_record(&mut reader, max_payload_bytes) {
            Ok(Some(rec)) => {
                result.records += 1;
                result.max_sequence = result.max_sequence.max(rec.sequence);
                result.valid_bytes += encoded_len(rec.payload.len()) as u64;
            }
            Ok(None) => break,
            Err(RecordError::Truncated) => {
                result.truncated = true;
                break;
            }
            Err(_) => {
                result.corrupt = true;
                break;
            }
        }
    }
    let file_len = file.metadata()?.len();
    if result.valid_bytes < file_len {
        file.set_len(result.valid_bytes)?;
    }
    Ok(result)
}

impl Spool {
    /// Open (creating if needed) the spool, healing any partial/corrupt segment tails.
    ///
    /// # Errors
    /// Returns an I/O error if the directory or segments cannot be read.
    pub fn open(config: SpoolConfig) -> io::Result<Self> {
        fs::create_dir_all(&config.dir)?;
        let mut indices: Vec<u64> = Vec::new();
        for entry in fs::read_dir(&config.dir)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if let Some(index) = parse_segment_index(&name) {
                indices.push(index);
            } else if is_stale_rewrite(&name) {
                // A rewrite that never reached its rename: the original segment is intact.
                fs::remove_file(entry.path())?;
            }
        }
        indices.sort_unstable();

        let mut spool = Self {
            config,
            segments: Vec::new(),
            active: None,
            next_index: 0,
            total_bytes: 0,
            corrupt_segments: 0,
            truncated_tail: false,
        };

        for index in indices {
            let path = spool.config.dir.join(segment_name(index));
            let scan = scan_and_heal(&path, spool.config.max_payload_bytes)?;
            if scan.corrupt {
                spool.corrupt_segments += 1;
            }
            spool.truncated_tail |= scan.truncated;
            spool.total_bytes += scan.valid_bytes;
            spool.next_index = index + 1;
            spool.segments.push(Segment {
                index,
                path,
                max_sequence: scan.max_sequence,
                records: scan.records,
                bytes: scan.valid_bytes,
            });
        }

        if let Some(last) = spool.segments.last() {
            spool.active = Some(OpenOptions::new().append(true).open(&last.path)?);
        }
        Ok(spool)
    }

    /// Append a record. Returns the number of records evicted from the oldest segment(s) to honor
    /// the disk limit (usually `0`).
    ///
    /// # Errors
    /// Returns [`SpoolError`] for oversized payloads or I/O failures.
    pub fn append(
        &mut self,
        sequence: u64,
        timestamp_micros: i64,
        payload: &[u8],
    ) -> Result<u64, SpoolError> {
        let payload_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        if payload_len > self.config.max_payload_bytes {
            return Err(SpoolError::PayloadTooLarge {
                len: payload_len,
                max: self.config.max_payload_bytes,
            });
        }
        let record_size = encoded_len(payload.len()) as u64;
        if record_size > self.config.disk_limit_bytes {
            return Err(SpoolError::RecordExceedsDiskLimit {
                size: record_size,
                limit: self.config.disk_limit_bytes,
            });
        }

        let evicted = self.evict_for(record_size)?;
        self.ensure_active_with_room(record_size)?;

        let encoded = record::encode(sequence, timestamp_micros, payload);
        if let Some(file) = self.active.as_mut() {
            file.write_all(&encoded)?;
            if self.config.fsync == FsyncPolicy::Always {
                file.sync_data()?;
            }
        }
        if let Some(last) = self.segments.last_mut() {
            last.bytes += record_size;
            last.records += 1;
            last.max_sequence = last.max_sequence.max(sequence);
        }
        self.total_bytes += record_size;
        Ok(evicted)
    }

    fn evict_for(&mut self, record_size: u64) -> io::Result<u64> {
        let mut evicted = 0;
        while self.total_bytes + record_size > self.config.disk_limit_bytes
            && self.segments.len() > 1
        {
            let seg = self.segments.remove(0);
            fs::remove_file(&seg.path)?;
            self.total_bytes -= seg.bytes;
            evicted += seg.records;
            tracing::warn!(
                segment = seg.index,
                records = seg.records,
                "spool evicted oldest segment to honor disk limit"
            );
        }
        Ok(evicted)
    }

    fn ensure_active_with_room(&mut self, record_size: u64) -> io::Result<()> {
        let need_new = match self.segments.last() {
            None => true,
            Some(last) => last.bytes > 0 && last.bytes + record_size > self.config.segment_bytes,
        };
        if need_new {
            let index = self.next_index;
            self.next_index += 1;
            let path = self.config.dir.join(segment_name(index));
            let file = OpenOptions::new().create(true).append(true).open(&path)?;
            self.active = Some(file);
            self.segments.push(Segment {
                index,
                path,
                max_sequence: 0,
                records: 0,
                bytes: 0,
            });
        }
        Ok(())
    }

    /// Replay every stored record in order. Records are guaranteed whole (the tail was healed on
    /// open).
    ///
    /// # Errors
    /// Returns an I/O error if a segment cannot be read.
    pub fn replay<F: FnMut(Record)>(&self, mut f: F) -> io::Result<ReplayStats> {
        let mut stats = ReplayStats {
            records: 0,
            corrupt_segments: self.corrupt_segments,
            truncated_tail: self.truncated_tail,
        };
        for seg in &self.segments {
            let mut reader = BufReader::new(File::open(&seg.path)?);
            loop {
                match record::read_record(&mut reader, self.config.max_payload_bytes) {
                    Ok(Some(rec)) => {
                        f(rec);
                        stats.records += 1;
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
        Ok(stats)
    }

    /// Rewrite stored records in place. `f` sees each whole record and returns a replacement payload,
    /// or `None` to keep it. Sequence numbers and timestamps are kept. A segment with no replaced
    /// record is not touched; one with any is written whole to `seg-….log.rewrite`, synced, and
    /// renamed over the original (then the directory is synced), so a crash leaves either the old
    /// segment or the new one, never a mix. Returns the number of records replaced.
    ///
    /// # Errors
    /// Returns an I/O error if a segment cannot be read or written, and `InvalidData` if a
    /// replacement exceeds the maximum record payload. Segments rewritten before the error stay
    /// rewritten; the one that failed, and those after it, stay as they were.
    pub fn rewrite<F: FnMut(&Record) -> Option<Vec<u8>>>(&mut self, mut f: F) -> io::Result<u64> {
        let mut replaced = 0;
        let last = self.segments.len().saturating_sub(1);
        for position in 0..self.segments.len() {
            let path = self.segments[position].path.clone();
            let records = read_segment(&path, self.config.max_payload_bytes)?;
            let mut changed = 0u64;
            let mut out = Vec::new();
            for rec in &records {
                match f(rec) {
                    Some(payload) => {
                        let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
                        if len > self.config.max_payload_bytes {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                SpoolError::PayloadTooLarge {
                                    len,
                                    max: self.config.max_payload_bytes,
                                },
                            ));
                        }
                        record::encode_into(&mut out, rec.sequence, rec.timestamp_micros, &payload);
                        changed += 1;
                    }
                    None => {
                        record::encode_into(
                            &mut out,
                            rec.sequence,
                            rec.timestamp_micros,
                            &rec.payload,
                        );
                    }
                }
            }
            if changed == 0 {
                continue;
            }
            let mut staged = path.clone().into_os_string();
            staged.push(REWRITE_SUFFIX);
            let staged = PathBuf::from(staged);
            {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&staged)?;
                file.write_all(&out)?;
                file.sync_all()?;
            }
            fs::rename(&staged, &path)?;
            sync_dir(&self.config.dir)?;
            let new_bytes = out.len() as u64;
            let segment = &mut self.segments[position];
            self.total_bytes = self.total_bytes - segment.bytes + new_bytes;
            segment.bytes = new_bytes;
            if position == last {
                // The append handle still points at the replaced file.
                self.active = Some(OpenOptions::new().append(true).open(&path)?);
            }
            replaced += changed;
        }
        Ok(replaced)
    }

    /// Delete fully-acknowledged segments whose highest sequence is `<= up_to_sequence`. The active
    /// segment is retained. Returns the number of records freed.
    ///
    /// # Errors
    /// Returns an I/O error if a segment file cannot be removed.
    pub fn ack(&mut self, up_to_sequence: u64) -> io::Result<u64> {
        let mut freed = 0;
        while self.segments.len() > 1 && self.segments[0].max_sequence <= up_to_sequence {
            let seg = self.segments.remove(0);
            fs::remove_file(&seg.path)?;
            self.total_bytes -= seg.bytes;
            freed += seg.records;
        }
        Ok(freed)
    }

    /// fsync the active segment.
    ///
    /// # Errors
    /// Returns an I/O error if the sync fails.
    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.active.as_mut() {
            file.sync_data()?;
        }
        Ok(())
    }

    /// Total bytes currently stored.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Number of segments.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Total records currently stored.
    #[must_use]
    pub fn record_count(&self) -> u64 {
        self.segments.iter().map(|s| s.records).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: PathBuf, segment_bytes: u64, disk_limit_bytes: u64) -> SpoolConfig {
        SpoolConfig {
            dir,
            segment_bytes,
            disk_limit_bytes,
            max_payload_bytes: 1024,
            fsync: FsyncPolicy::Never,
        }
    }

    fn collect(spool: &Spool) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        spool
            .replay(|r| out.push((r.sequence, r.payload)))
            .expect("replay");
        out
    }

    #[test]
    fn append_and_replay_round_trips() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut spool = Spool::open(config(dir.path().into(), 1 << 20, 1 << 30)).expect("open");
        for i in 1..=5u64 {
            spool
                .append(i, i as i64, format!("payload-{i}").as_bytes())
                .expect("append");
        }
        let records = collect(&spool);
        assert_eq!(records.len(), 5);
        assert_eq!(records[0], (1, b"payload-1".to_vec()));
        assert_eq!(records[4], (5, b"payload-5".to_vec()));
    }

    #[test]
    fn survives_restart_and_replays_unacked() {
        let dir = tempfile::tempdir().expect("tmp");
        {
            let mut spool = Spool::open(config(dir.path().into(), 1 << 20, 1 << 30)).expect("open");
            spool.append(1, 1, b"a").expect("a");
            spool.append(2, 2, b"b").expect("b");
            spool.flush().expect("flush");
        }
        // Reopen: data persists.
        let spool = Spool::open(config(dir.path().into(), 1 << 20, 1 << 30)).expect("reopen");
        assert_eq!(collect(&spool).len(), 2);
    }

    #[test]
    fn truncated_final_record_is_healed_on_open() {
        let dir = tempfile::tempdir().expect("tmp");
        let seg_path;
        {
            let mut spool = Spool::open(config(dir.path().into(), 1 << 20, 1 << 30)).expect("open");
            spool.append(1, 1, b"first").expect("first");
            spool.append(2, 2, b"second").expect("second");
            seg_path = dir.path().join(segment_name(0));
        }
        // Simulate a crash mid-write: drop the last few bytes of the file.
        let len = fs::metadata(&seg_path).expect("meta").len();
        let file = OpenOptions::new()
            .write(true)
            .open(&seg_path)
            .expect("open");
        file.set_len(len - 3).expect("truncate");

        let spool = Spool::open(config(dir.path().into(), 1 << 20, 1 << 30)).expect("reopen");
        let records = collect(&spool);
        assert_eq!(records.len(), 1, "only the whole record survives");
        assert_eq!(records[0].0, 1);
        assert!(spool.truncated_tail);
    }

    #[test]
    fn corrupt_record_stops_replay_at_that_point() {
        let dir = tempfile::tempdir().expect("tmp");
        let seg_path;
        {
            let mut spool = Spool::open(config(dir.path().into(), 1 << 20, 1 << 30)).expect("open");
            spool.append(1, 1, b"good-one").expect("1");
            spool.append(2, 2, b"good-two").expect("2");
            seg_path = dir.path().join(segment_name(0));
        }
        // Corrupt a byte inside the FIRST record's payload.
        let mut bytes = fs::read(&seg_path).expect("read");
        bytes[record::HEADER_LEN + 1] ^= 0xff;
        fs::write(&seg_path, &bytes).expect("write");

        let spool = Spool::open(config(dir.path().into(), 1 << 20, 1 << 30)).expect("reopen");
        // First record corrupt -> healed away; nothing replays, corruption is reported (not silent).
        assert_eq!(collect(&spool).len(), 0);
        assert_eq!(spool.corrupt_segments, 1);
    }

    #[test]
    fn rotation_spans_multiple_segments() {
        let dir = tempfile::tempdir().expect("tmp");
        // Tiny segments force rotation on nearly every record.
        let mut spool = Spool::open(config(dir.path().into(), 40, 1 << 30)).expect("open");
        for i in 1..=10u64 {
            spool.append(i, i as i64, b"xyz").expect("append");
        }
        assert!(spool.segment_count() > 1, "should have rotated");
        let records = collect(&spool);
        assert_eq!(records.len(), 10);
        assert_eq!(
            records.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            (1..=10).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ack_deletes_fully_acknowledged_segments() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut spool = Spool::open(config(dir.path().into(), 40, 1 << 30)).expect("open");
        for i in 1..=10u64 {
            spool.append(i, i as i64, b"xyz").expect("append");
        }
        let segments_before = spool.segment_count();
        let bytes_before = spool.total_bytes();
        let freed = spool.ack(3).expect("ack");
        assert!(freed >= 1, "some records freed");
        assert!(spool.segment_count() < segments_before);
        assert!(spool.total_bytes() < bytes_before);
        // Records with sequence <= 3 in deleted segments are gone; later ones remain.
        let remaining: Vec<u64> = collect(&spool).into_iter().map(|(s, _)| s).collect();
        assert!(remaining.contains(&10));
        assert!(!remaining.contains(&1));
    }

    #[test]
    fn disk_limit_evicts_oldest() {
        let dir = tempfile::tempdir().expect("tmp");
        // Small segments and a small disk budget -> oldest segments evicted.
        let mut spool = Spool::open(config(dir.path().into(), 40, 200)).expect("open");
        let mut total_evicted = 0;
        for i in 1..=20u64 {
            total_evicted += spool.append(i, i as i64, b"xyz").expect("append");
        }
        assert!(total_evicted > 0, "disk limit should have evicted records");
        assert!(spool.total_bytes() <= 200 + encoded_len(3) as u64);
        // The most recent record is always retained.
        let remaining: Vec<u64> = collect(&spool).into_iter().map(|(s, _)| s).collect();
        assert!(remaining.contains(&20));
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut spool = Spool::open(config(dir.path().into(), 1 << 20, 1 << 30)).expect("open");
        let big = vec![0u8; 2048]; // > max_payload_bytes (1024)
        assert!(matches!(
            spool.append(1, 1, &big),
            Err(SpoolError::PayloadTooLarge { max: 1024, .. })
        ));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn spool_bytes(dir: &Path) -> Vec<u8> {
        let mut all = Vec::new();
        for entry in fs::read_dir(dir).expect("dir") {
            all.extend(fs::read(entry.expect("entry").path()).expect("read"));
        }
        all
    }

    #[test]
    fn rewrite_replaces_records_in_every_segment_and_keeps_the_rest() {
        let dir = tempfile::tempdir().expect("tmp");
        // Tiny segments: the secret lands in an older segment and in the active one.
        let mut spool = Spool::open(config(dir.path().into(), 60, 1 << 30)).expect("open");
        spool.append(1, 1, b"keep-one").expect("1");
        spool.append(2, 2, b"secret-a").expect("2");
        spool.append(3, 3, b"keep-two").expect("3");
        spool.append(4, 4, b"secret-b").expect("4");
        assert!(spool.segment_count() > 1);
        assert!(contains(&spool_bytes(dir.path()), b"secret"));

        let replaced = spool
            .rewrite(|r| r.payload.starts_with(b"secret").then(|| b"gone".to_vec()))
            .expect("rewrite");
        assert_eq!(replaced, 2);
        assert!(!contains(&spool_bytes(dir.path()), b"secret"));
        assert_eq!(
            collect(&spool),
            vec![
                (1, b"keep-one".to_vec()),
                (2, b"gone".to_vec()),
                (3, b"keep-two".to_vec()),
                (4, b"gone".to_vec()),
            ]
        );
        let on_disk: u64 = fs::read_dir(dir.path())
            .expect("dir")
            .map(|e| e.expect("entry").metadata().expect("meta").len())
            .sum();
        assert_eq!(spool.total_bytes(), on_disk);

        // The active segment's append handle follows the rename.
        spool.append(5, 5, b"after").expect("5");
        drop(spool);
        let reopened = Spool::open(config(dir.path().into(), 60, 1 << 30)).expect("reopen");
        let records = collect(&reopened);
        assert_eq!(records.len(), 5);
        assert_eq!(records[4], (5, b"after".to_vec()));
    }

    #[test]
    fn rewrite_leaves_untouched_segments_alone_and_open_drops_a_stale_rewrite() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut spool = Spool::open(config(dir.path().into(), 1 << 20, 1 << 30)).expect("open");
        spool.append(1, 1, b"a").expect("a");
        let seg = dir.path().join(segment_name(0));
        let before = fs::metadata(&seg).expect("meta").modified().expect("mtime");
        assert_eq!(spool.rewrite(|_| None).expect("rewrite"), 0);
        assert_eq!(
            fs::metadata(&seg).expect("meta").modified().expect("mtime"),
            before
        );
        drop(spool);

        // A crash between writing the staged copy and renaming it.
        let stale = dir
            .path()
            .join(format!("{}{REWRITE_SUFFIX}", segment_name(0)));
        fs::write(&stale, b"half-written").expect("stale");
        let spool = Spool::open(config(dir.path().into(), 1 << 20, 1 << 30)).expect("reopen");
        assert!(!stale.exists());
        assert_eq!(collect(&spool), vec![(1, b"a".to_vec())]);
    }

    #[test]
    fn replay_is_idempotent() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut spool = Spool::open(config(dir.path().into(), 1 << 20, 1 << 30)).expect("open");
        spool.append(1, 1, b"a").expect("a");
        spool.append(2, 2, b"b").expect("b");
        assert_eq!(collect(&spool), collect(&spool));
    }
}
