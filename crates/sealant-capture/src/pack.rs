//! CDC pack container (ADR-0015 amendment decision 4): a sequence of zstd-compressed chunks, a
//! trailing JSON index of `{ hash, offset, length, size }`, an 8-byte little-endian index length,
//! and the magic `SLCP0001`. A pack is at most 64 MiB, one PUT, keyed by the sha256 of its bytes.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chunk::ChunkId;

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

/// Incremental writer for one pack.
#[derive(Debug)]
pub struct PackWriter {
    file: BufWriter<File>,
    path: PathBuf,
    hasher: Sha256,
    offset: u64,
    entries: Vec<PackIndexEntry>,
    cap: u64,
}

impl PackWriter {
    /// Start a pack at `path` (a temporary name; [`PackWriter::finish`] renames it beside itself).
    pub fn create(path: &Path, cap: u64) -> io::Result<Self> {
        Ok(Self {
            file: BufWriter::new(File::create(path)?),
            path: path.to_path_buf(),
            hasher: Sha256::new(),
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
        self.file.write_all(compressed)?;
        self.hasher.update(compressed);
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
    pub fn finish(mut self) -> Result<FinishedPack, PackError> {
        let index = serde_json::to_vec(&self.entries)?;
        self.file.write_all(&index)?;
        self.hasher.update(&index);
        let len = (index.len() as u64).to_le_bytes();
        self.file.write_all(&len)?;
        self.hasher.update(len);
        self.file.write_all(&PACK_MAGIC)?;
        self.hasher.update(PACK_MAGIC);
        self.file.flush()?;
        let file = self
            .file
            .into_inner()
            .map_err(io::IntoInnerError::into_error)?;
        file.sync_data()?;
        let bytes = self.offset + index.len() as u64 + TRAILER_LEN;
        let sha256 = hex::encode(self.hasher.finalize());
        let final_path = self
            .path
            .parent()
            .map_or_else(|| PathBuf::from(&sha256), |p| p.join(&sha256));
        fs::rename(&self.path, &final_path)?;
        Ok(FinishedPack {
            path: final_path,
            sha256,
            bytes,
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
    finished: Vec<FinishedPack>,
    seen: HashMap<ChunkId, ()>,
    counter: u64,
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
        }
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
            let writer = PackWriter::create(&tmp, self.cap)?;
            if !writer.fits(clen) {
                fs::remove_file(&tmp).ok();
                return Err(PackError::ChunkTooLarge(clen));
            }
            self.current = Some(writer);
        }
        if let Some(w) = self.current.as_mut() {
            w.append(id, &compressed, data.len() as u64)?;
        }
        self.seen.insert(id, ());
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), PackError> {
        if let Some(w) = self.current.take() {
            if w.is_empty() {
                fs::remove_file(&w.path).ok();
            } else {
                self.finished.push(w.finish()?);
            }
        }
        Ok(())
    }

    /// Finish the open pack and return every pack written.
    pub fn finish(mut self) -> Result<Vec<FinishedPack>, PackError> {
        self.rotate()?;
        Ok(self.finished)
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
