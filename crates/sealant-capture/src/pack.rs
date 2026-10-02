//! CDC pack container (ADR-0015 amendment decision 4): a sequence of zstd-compressed chunks, a
//! trailing JSON index of `{ hash, offset, length, size }`, an 8-byte little-endian index length,
//! and the magic `SLCP0001`. A pack is at most 64 MiB, one PUT, keyed by the sha256 of its bytes.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::thread::{self, JoinHandle};

use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};

use crate::chunk::ChunkId;
use crate::io_at::IoAt;

/// Trailing magic.
pub const PACK_MAGIC: [u8; 8] = *b"SLCP0001";
/// Pack size cap (ADR-0015: ≤ 64 MiB, one PUT, never multipart).
pub const MAX_PACK_BYTES: u64 = 64 * 1024 * 1024;
/// zstd level for chunks: fast, with real compression for text and JSON.
pub const ZSTD_LEVEL: i32 = 3;
const TRAILER_LEN: u64 = 16;
/// Conservative per-entry size of the JSON index, used for the cap check before finishing.
const INDEX_ENTRY_ESTIMATE: u64 = 160;

/// One entry of a pack's trailing index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackIndexEntry {
    /// sha256 of the uncompressed chunk.
    pub hash: ChunkId,
    /// Byte offset of the compressed chunk within the pack.
    pub offset: u64,
    /// Compressed length in bytes.
    pub length: u64,
    /// Uncompressed size in bytes.
    pub size: u64,
}

/// Pack errors.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    /// Missing or wrong trailing magic.
    #[error("not a CDC pack: bad magic or truncated trailer")]
    BadMagic,
    /// The trailing index length does not fit the pack.
    #[error("pack index length {0} does not fit the pack")]
    BadIndexLength(u64),
    /// The trailing index is not valid JSON.
    #[error("pack index is not valid JSON: {0}")]
    BadIndex(#[from] serde_json::Error),
    /// A chunk's bytes did not hash to its id.
    #[error("chunk {expected} read back as {actual}")]
    ChunkMismatch {
        /// Id the index promised.
        expected: ChunkId,
        /// Id of the bytes read.
        actual: ChunkId,
    },
    /// A single chunk would exceed the pack cap.
    #[error("chunk of {0} compressed bytes cannot fit an empty pack")]
    ChunkTooLarge(u64),
    /// I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Compress one chunk.
pub fn compress_chunk(data: &[u8]) -> io::Result<Vec<u8>> {
    zstd::bulk::compress(data, ZSTD_LEVEL)
}

/// Decompress one chunk whose uncompressed size is known.
pub fn decompress_chunk(data: &[u8], size: usize) -> io::Result<Vec<u8>> {
    zstd::bulk::decompress(data, size)
}

/// A finished pack on disk, renamed to its sha256.
#[derive(Debug, Clone)]
pub struct FinishedPack {
    /// Path of the pack file (its file name is `sha256`).
    pub path: PathBuf,
    /// Lowercase hex sha256 of the whole pack.
    pub sha256: String,
    /// Size of the pack file.
    pub bytes: u64,
    /// The trailing index.
    pub entries: Vec<PackIndexEntry>,
}

/// Buffers a pack's hashing thread may hold before the writer waits for it.
const HASH_AHEAD_BUFFERS: usize = 32;

/// The sha256 of a pack as it is written: on the writer's thread, or on one of its own.
///
/// A pack's digest covers every byte in order, so one thread computes it. On the writer's own
/// thread that was a quarter of a final flush on a CPU without SHA extensions (2026-10-02: 788 MB
/// of packs, 2.6 s). A build nothing competes with hands the bytes to a thread per pack instead,
/// and keeps writing.
enum PackHasher {
    Here(Box<Context>),
    Ahead {
        bytes: SyncSender<Vec<u8>>,
        digest: JoinHandle<String>,
    },
}

impl PackHasher {
    fn new(ahead: bool) -> Self {
        if ahead {
            let (bytes, queue) = mpsc::sync_channel::<Vec<u8>>(HASH_AHEAD_BUFFERS);
            let spawned = thread::Builder::new()
                .name("capture-pack-hash".to_owned())
                .spawn(move || {
                    let mut hasher = Context::new(&SHA256);
                    for buffer in queue {
                        hasher.update(&buffer);
                    }
                    hex::encode(hasher.finish())
                });
            if let Ok(digest) = spawned {
                return Self::Ahead { bytes, digest };
            }
        }
        Self::Here(Box::new(Context::new(&SHA256)))
    }

    fn update(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Here(hasher) => {
                hasher.update(data);
                Ok(())
            }
            Self::Ahead { bytes, .. } => bytes
                .send(data.to_vec())
                .map_err(|_| io::Error::other("the pack hashing thread stopped")),
        }
    }

    fn finish(self) -> io::Result<String> {
        match self {
            Self::Here(hasher) => Ok(hex::encode(hasher.finish())),
            Self::Ahead { bytes, digest } => {
                // The thread ends once nothing can send it bytes.
                drop(bytes);
                digest
                    .join()
                    .map_err(|_| io::Error::other("the pack hashing thread panicked"))
            }
        }
    }
}

impl fmt::Debug for PackHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Here(_) => "PackHasher::Here",
            Self::Ahead { .. } => "PackHasher::Ahead",
        })
    }
}

/// A pack with every byte written, not yet synced, named or hashed to the end
/// ([`PackWriter::seal`]).
#[derive(Debug)]
struct SealedPack {
    file: File,
    path: PathBuf,
    hasher: PackHasher,
    bytes: u64,
    entries: Vec<PackIndexEntry>,
}

impl SealedPack {
    /// Sync the file, take its digest and rename it to that.
    fn complete(self) -> Result<FinishedPack, PackError> {
        self.file.sync_data().at("sync", &self.path)?;
        let sha256 = self.hasher.finish().at("hash", &self.path)?;
        let final_path = self
            .path
            .parent()
            .map_or_else(|| PathBuf::from(&sha256), |p| p.join(&sha256));
        fs::rename(&self.path, &final_path).at("rename into", &final_path)?;
        Ok(FinishedPack {
            path: final_path,
            sha256,
            bytes: self.bytes,
            entries: self.entries,
        })
    }
}

/// A pack a [`PackBuilder`] is done writing: finished, or finishing on a thread of its own.
#[derive(Debug)]
enum Finishing {
    Done(FinishedPack),
    Ahead(JoinHandle<Result<FinishedPack, PackError>>),
}

/// Incremental writer for one pack.
#[derive(Debug)]
pub struct PackWriter {
    file: BufWriter<File>,
    path: PathBuf,
    hasher: PackHasher,
    offset: u64,
    entries: Vec<PackIndexEntry>,
    cap: u64,
}

impl PackWriter {
    /// Start a pack at `path` (a temporary name; [`PackWriter::finish`] renames it beside itself).
    pub fn create(path: &Path, cap: u64) -> io::Result<Self> {
        Self::create_hashing(path, cap, false)
    }

    /// [`Self::create`], its digest computed on a thread of its own when `hash_ahead`.
    pub fn create_hashing(path: &Path, cap: u64, hash_ahead: bool) -> io::Result<Self> {
        Ok(Self {
            file: BufWriter::new(File::create(path).at("create", path)?),
            path: path.to_path_buf(),
            hasher: PackHasher::new(hash_ahead),
            offset: 0,
            entries: Vec::new(),
            cap,
        })
    }

    /// Whether a compressed chunk of `compressed_len` bytes fits under the cap.
    #[must_use]
    pub fn fits(&self, compressed_len: u64) -> bool {
        let index_estimate = (self.entries.len() as u64 + 1) * INDEX_ENTRY_ESTIMATE;
        self.offset + compressed_len + index_estimate + TRAILER_LEN <= self.cap
    }

    /// Whether nothing has been appended yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of chunks appended so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Append an already-compressed chunk.
    pub fn append(&mut self, hash: ChunkId, compressed: &[u8], size: u64) -> io::Result<()> {
        self.file.write_all(compressed).at("write", &self.path)?;
        self.hasher.update(compressed).at("hash", &self.path)?;
        self.entries.push(PackIndexEntry {
            hash,
            offset: self.offset,
            length: compressed.len() as u64,
            size,
        });
        self.offset += compressed.len() as u64;
        Ok(())
    }

    /// Write the trailer, rename the file to its sha256 and return the finished pack.
    pub fn finish(self) -> Result<FinishedPack, PackError> {
        self.seal()?.complete()
    }

    /// Write the trailer: every byte of the pack is in the file, and handed to its hasher.
    fn seal(mut self) -> Result<SealedPack, PackError> {
        let index = serde_json::to_vec(&self.entries)?;
        let path = self.path.clone();
        self.file.write_all(&index).at("write", &path)?;
        self.hasher.update(&index).at("hash", &path)?;
        let len = (index.len() as u64).to_le_bytes();
        self.file.write_all(&len).at("write", &path)?;
        self.hasher.update(&len).at("hash", &path)?;
        self.file.write_all(&PACK_MAGIC).at("write", &path)?;
        self.hasher.update(&PACK_MAGIC).at("hash", &path)?;
        self.file.flush().at("write", &path)?;
        let file = self
            .file
            .into_inner()
            .map_err(io::IntoInnerError::into_error)
            .at("write", &path)?;
        Ok(SealedPack {
            file,
            path,
            hasher: self.hasher,
            bytes: self.offset + index.len() as u64 + TRAILER_LEN,
            entries: self.entries,
        })
    }
}

/// Builds one or more packs from a stream of chunks, rotating at the cap and skipping chunks
/// already added to this builder.
#[derive(Debug)]
pub struct PackBuilder {
    dir: PathBuf,
    cap: u64,
    current: Option<PackWriter>,
    finished: Vec<Finishing>,
    seen: HashMap<ChunkId, ()>,
    counter: u64,
    hash_ahead: bool,
}

impl PackBuilder {
    /// Packs are written into `dir` (which must exist).
    #[must_use]
    pub fn new(dir: &Path, cap: u64) -> Self {
        Self {
            dir: dir.to_path_buf(),
            cap,
            current: None,
            finished: Vec::new(),
            seen: HashMap::new(),
            counter: 0,
            hash_ahead: false,
        }
    }

    /// Compute each pack's digest on a thread of its own (a build nothing competes with).
    #[must_use]
    pub fn hash_ahead(mut self, hash_ahead: bool) -> Self {
        self.hash_ahead = hash_ahead;
        self
    }

    /// Whether this builder already holds `id`.
    #[must_use]
    pub fn contains(&self, id: &ChunkId) -> bool {
        self.seen.contains_key(id)
    }

    /// Add a chunk (no-op if already added).
    pub fn add(&mut self, id: ChunkId, data: &[u8]) -> Result<(), PackError> {
        if self.seen.contains_key(&id) {
            return Ok(());
        }
        let compressed = compress_chunk(data)?;
        self.add_packed(id, data.len() as u64, &compressed)
    }

    /// Add a chunk already compressed with [`compress_chunk`], `size` bytes uncompressed (no-op
    /// if already added).
    pub fn add_packed(
        &mut self,
        id: ChunkId,
        size: u64,
        compressed: &[u8],
    ) -> Result<(), PackError> {
        if self.seen.contains_key(&id) {
            return Ok(());
        }
        let clen = compressed.len() as u64;
        let rotate = self
            .current
            .as_ref()
            .is_some_and(|w| !w.is_empty() && !w.fits(clen));
        if rotate {
            self.rotate()?;
        }
        if self.current.is_none() {
            self.counter += 1;
            let tmp = self.dir.join(format!(".pack-{}.tmp", self.counter));
            let writer = PackWriter::create_hashing(&tmp, self.cap, self.hash_ahead)?;
            if !writer.fits(clen) {
                fs::remove_file(&tmp).ok();
                return Err(PackError::ChunkTooLarge(clen));
            }
            self.current = Some(writer);
        }
        if let Some(w) = self.current.as_mut() {
            w.append(id, compressed, size)?;
        }
        self.seen.insert(id, ());
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), PackError> {
        if let Some(w) = self.current.take() {
            if w.is_empty() {
                fs::remove_file(&w.path).ok();
            } else if self.hash_ahead {
                // The build goes on to the next pack while this one is synced and named. A
                // sync was a second of a final flush on a slow disk (2026-10-02).
                let sealed = w.seal()?;
                let path = sealed.path.clone();
                let finishing = thread::Builder::new()
                    .name("capture-pack-end".to_owned())
                    .spawn(move || sealed.complete())
                    .at("finish", &path)?;
                self.finished.push(Finishing::Ahead(finishing));
            } else {
                self.finished.push(Finishing::Done(w.finish()?));
            }
        }
        Ok(())
    }

    /// Finish the open pack and return every pack written.
    pub fn finish(mut self) -> Result<Vec<FinishedPack>, PackError> {
        self.rotate()?;
        self.finished
            .into_iter()
            .map(|pack| match pack {
                Finishing::Done(pack) => Ok(pack),
                Finishing::Ahead(finishing) => finishing.join().unwrap_or_else(|_| {
                    Err(PackError::Io(io::Error::other(
                        "the thread finishing a pack panicked",
                    )))
                }),
            })
            .collect()
    }
}

/// Parse a pack's trailing index from its full bytes (`total` = pack length; `tail` = at least
/// the last 16 bytes; `read_index` supplies the index bytes given `(offset, len)`).
fn parse_trailer(tail: &[u8], total: u64) -> Result<(u64, u64), PackError> {
    if tail.len() < TRAILER_LEN as usize || total < TRAILER_LEN {
        return Err(PackError::BadMagic);
    }
    let t = &tail[tail.len() - TRAILER_LEN as usize..];
    if t[8..16] != PACK_MAGIC {
        return Err(PackError::BadMagic);
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&t[0..8]);
    let index_len = u64::from_le_bytes(len_bytes);
    if index_len > total - TRAILER_LEN {
        return Err(PackError::BadIndexLength(index_len));
    }
    Ok((total - TRAILER_LEN - index_len, index_len))
}

/// Parse the trailing index out of a whole pack held in memory.
pub fn parse_index(pack: &[u8]) -> Result<Vec<PackIndexEntry>, PackError> {
    let (offset, len) = parse_trailer(pack, pack.len() as u64)?;
    let start = usize::try_from(offset).map_err(|_| PackError::BadIndexLength(len))?;
    let end = usize::try_from(offset + len).map_err(|_| PackError::BadIndexLength(len))?;
    Ok(serde_json::from_slice(&pack[start..end])?)
}

/// Random-access reader over a pack file.
#[derive(Debug)]
pub struct PackReader {
    file: File,
    entries: HashMap<ChunkId, PackIndexEntry>,
}

impl PackReader {
    /// Open a pack file and parse its trailing index.
    pub fn open(path: &Path) -> Result<Self, PackError> {
        let mut file = File::open(path)?;
        let total = file.metadata()?.len();
        if total < TRAILER_LEN {
            return Err(PackError::BadMagic);
        }
        file.seek(SeekFrom::Start(total - TRAILER_LEN))?;
        let mut tail = [0u8; 16];
        file.read_exact(&mut tail)?;
        let (offset, len) = parse_trailer(&tail, total)?;
        let mut index =
            vec![0u8; usize::try_from(len).map_err(|_| PackError::BadIndexLength(len))?];
        file.read_exact_at(&mut index, offset)?;
        let entries: Vec<PackIndexEntry> = serde_json::from_slice(&index)?;
        Ok(Self {
            file,
            entries: entries.into_iter().map(|e| (e.hash, e)).collect(),
        })
    }

    /// Chunk ids this pack holds.
    pub fn chunk_ids(&self) -> impl Iterator<Item = &ChunkId> {
        self.entries.keys()
    }

    /// Whether the pack holds `id`.
    #[must_use]
    pub fn contains(&self, id: &ChunkId) -> bool {
        self.entries.contains_key(id)
    }

    /// Read and verify one chunk; `Ok(None)` if the pack does not hold it.
    pub fn read(&self, id: &ChunkId) -> Result<Option<Vec<u8>>, PackError> {
        let Some(entry) = self.entries.get(id) else {
            return Ok(None);
        };
        let mut compressed = vec![
            0u8;
            usize::try_from(entry.length)
                .map_err(|_| PackError::BadIndexLength(entry.length))?
        ];
        self.file.read_exact_at(&mut compressed, entry.offset)?;
        let size =
            usize::try_from(entry.size).map_err(|_| PackError::BadIndexLength(entry.size))?;
        let data = decompress_chunk(&compressed, size)?;
        let actual = ChunkId::of(&data);
        if actual != *id {
            return Err(PackError::ChunkMismatch {
                expected: *id,
                actual,
            });
        }
        Ok(Some(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_hashed_and_finished_ahead_are_the_same_packs() {
        let build = |ahead: bool| {
            let dir = tempfile::tempdir().unwrap();
            // A small cap: several packs, so several finish while the next is written.
            let mut b = PackBuilder::new(dir.path(), 256 * 1024).hash_ahead(ahead);
            for n in 0..40u64 {
                let data = pseudo_random(20_000 + usize::try_from(n).unwrap() * 37, n + 1);
                b.add(ChunkId::of(&data), &data).unwrap();
            }
            let packs = b.finish().unwrap();
            for pack in &packs {
                let stored = fs::read(&pack.path).unwrap();
                assert_eq!(stored.len() as u64, pack.bytes);
                assert_eq!(crate::chunk::sha256_hex(&stored), pack.sha256);
                assert_eq!(
                    pack.path.file_name().unwrap().to_str().unwrap(),
                    pack.sha256
                );
            }
            // Nothing is left under a temporary name.
            let names: Vec<String> = fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
            packs
                .into_iter()
                .map(|p| (p.sha256, p.bytes, p.entries))
                .collect::<Vec<_>>()
        };
        let here = build(false);
        assert!(here.len() > 2, "several packs: {}", here.len());
        assert_eq!(build(true), here);
    }

    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24 & 0xff) as u8
            })
            .collect()
    }

    #[test]
    fn round_trip_and_trailer_layout() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = PackBuilder::new(dir.path(), MAX_PACK_BYTES);
        let a = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let c = pseudo_random(300_000, 3);
        b.add(ChunkId::of(&a), &a).unwrap();
        b.add(ChunkId::of(&c), &c).unwrap();
        b.add(ChunkId::of(&a), &a).unwrap(); // duplicate ignored
        let packs = b.finish().unwrap();
        assert_eq!(packs.len(), 1);
        let p = &packs[0];
        assert_eq!(p.entries.len(), 2);
        let bytes = fs::read(&p.path).unwrap();
        assert_eq!(bytes.len() as u64, p.bytes);
        assert_eq!(&bytes[bytes.len() - 8..], &PACK_MAGIC);
        assert_eq!(crate::chunk::sha256_hex(&bytes), p.sha256);
        assert_eq!(p.path.file_name().unwrap().to_str().unwrap(), p.sha256);
        assert_eq!(parse_index(&bytes).unwrap(), p.entries);

        let r = PackReader::open(&p.path).unwrap();
        assert_eq!(r.read(&ChunkId::of(&a)).unwrap().unwrap(), a);
        assert_eq!(r.read(&ChunkId::of(&c)).unwrap().unwrap(), c);
        assert!(r.read(&ChunkId::of(b"nope")).unwrap().is_none());
    }

    #[test]
    fn spills_into_a_second_pack_past_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        // Incompressible chunks of 1 MiB with a 4 MiB cap: five chunks must need two packs.
        let cap = 4 * 1024 * 1024;
        let mut b = PackBuilder::new(dir.path(), cap);
        let mut ids = Vec::new();
        for i in 0..5u64 {
            let data = pseudo_random(1024 * 1024, 1000 + i);
            let id = ChunkId::of(&data);
            b.add(id, &data).unwrap();
            ids.push((id, data));
        }
        let packs = b.finish().unwrap();
        assert_eq!(packs.len(), 2, "expected a spill into a second pack");
        for p in &packs {
            assert!(p.bytes <= cap, "pack {} over cap", p.bytes);
        }
        let readers: Vec<_> = packs
            .iter()
            .map(|p| PackReader::open(&p.path).unwrap())
            .collect();
        for (id, data) in &ids {
            let found = readers.iter().find_map(|r| r.read(id).unwrap());
            assert_eq!(found.as_deref(), Some(data.as_slice()));
        }
    }

    #[test]
    fn corrupt_chunk_is_detected_on_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = PackBuilder::new(dir.path(), MAX_PACK_BYTES);
        let data = pseudo_random(100_000, 5);
        let id = ChunkId::of(&data);
        b.add(id, &data).unwrap();
        let packs = b.finish().unwrap();
        let mut bytes = fs::read(&packs[0].path).unwrap();
        bytes[10] ^= 0xff;
        let corrupt = dir.path().join("corrupt");
        fs::write(&corrupt, &bytes).unwrap();
        let r = PackReader::open(&corrupt).unwrap();
        assert!(r.read(&id).is_err());
        assert!(matches!(
            PackReader::open(&dir.path().join("missing")),
            Err(PackError::Io(_))
        ));
        fs::write(&corrupt, b"short").unwrap();
        assert!(matches!(
            PackReader::open(&corrupt),
            Err(PackError::BadMagic)
        ));
    }
}
