//! Content-defined chunking (FastCDC v2020, 256 KiB / 1 MiB / 4 MiB) and chunk identity: the
//! sha256 of a chunk's uncompressed bytes.

use std::fmt;
use std::io::{self, BufReader, Cursor, Read};

use fastcdc::v2020::StreamCDC;
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Minimum chunk size (ADR-0015: 256 KiB). Files below this size are one chunk.
pub const MIN_CHUNK_SIZE: usize = 256 * 1024;
/// Average (target) chunk size (ADR-0015: 1 MiB).
pub const AVG_CHUNK_SIZE: usize = 1024 * 1024;
/// Maximum chunk size (ADR-0015: 4 MiB).
pub const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// A sha256 digest, used for chunk ids and every other content address in the store.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkId([u8; 32]);

impl ChunkId {
    /// Digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut id = [0u8; 32];
        id.copy_from_slice(digest(&SHA256, bytes).as_ref());
        Self(id)
    }

    /// Wrap a raw digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Lowercase hex form (the on-the-wire and key form).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a lowercase hex digest.
    #[must_use]
    pub fn parse(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(Self(arr))
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkId({})", self.to_hex())
    }
}

impl Serialize for ChunkId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ChunkId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("bad sha256 hex: {s}")))
    }
}

/// Lowercase hex sha256 of `bytes` (packs, dir objects and manifests are keyed by this).
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(digest(&SHA256, bytes))
}

/// One chunk of a file: its id and uncompressed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// sha256 of `data`.
    pub id: ChunkId,
    /// Uncompressed bytes.
    pub data: Vec<u8>,
}

/// Streaming chunker over any reader.
pub struct ChunkStream<R: Read> {
    inner: StreamCDC<R>,
}

impl<R: Read> fmt::Debug for ChunkStream<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChunkStream")
    }
}

impl<R: Read> Iterator for ChunkStream<R> {
    type Item = std::io::Result<Chunk>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next()? {
            Ok(cd) => Some(Ok(Chunk {
                id: ChunkId::of(&cd.data),
                data: cd.data,
            })),
            Err(fastcdc::v2020::Error::Empty) => None,
            Err(e) => Some(Err(std::io::Error::from(e))),
        }
    }
}

/// Chunk `reader` with the ADR-0015 parameters. An empty reader yields no chunks.
pub fn chunk_reader<R: Read>(reader: R) -> ChunkStream<R> {
    ChunkStream {
        inner: StreamCDC::new(reader, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE),
    }
}

/// A file's first bytes, read to see how long it is, then the rest of it.
type HeadThenRest<R> = io::Chain<Cursor<Vec<u8>>, BufReader<R>>;

/// One file cut where the chunker cuts it, each part's bytes not yet hashed ([`file_parts`]).
pub enum FileParts<R: Read> {
    /// At most [`MIN_CHUNK_SIZE`] bytes: one part, or none when empty.
    Whole(Option<Vec<u8>>),
    /// Longer: the bytes already read, then the rest, through the chunker.
    Stream(Box<StreamCDC<HeadThenRest<R>>>),
}

impl<R: Read> fmt::Debug for FileParts<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileParts")
    }
}

impl<R: Read> Iterator for FileParts<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Whole(part) => part.take().map(Ok),
            Self::Stream(stream) => match stream.next()? {
                Ok(cd) => Some(Ok(cd.data)),
                Err(fastcdc::v2020::Error::Empty) => None,
                Err(e) => Some(Err(io::Error::from(e))),
            },
        }
    }
}

/// The chunks of one file ([`chunk_file`]): its parts, each hashed.
#[derive(Debug)]
pub struct FileChunks<R: Read>(FileParts<R>);

impl<R: Read> Iterator for FileChunks<R> {
    type Item = io::Result<Chunk>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.0.next()?.map(|data| Chunk {
            id: ChunkId::of(&data),
            data,
        }))
    }
}

/// Chunk a file exactly as [`chunk_reader`] does, without its cost for a small one. The chunker
/// zeroes a [`MAX_CHUNK_SIZE`] buffer for every reader it is given, and FastCDC returns an input
/// of at most [`MIN_CHUNK_SIZE`] bytes as one chunk: a dependency tree is a hundred thousand
/// such files, and the zeroing was most of the time a snap of one took (2026-10-02). So the first
/// `MIN_CHUNK_SIZE + 1` bytes are read first: a file that ends within them is its one chunk, and
/// a longer one goes through the chunker from its first byte.
pub fn chunk_file<R: Read>(reader: R) -> io::Result<FileChunks<R>> {
    Ok(FileChunks(file_parts(reader)?))
}

/// [`chunk_file`] without the hashing: the same cuts, for a caller that hashes the parts itself
/// (on other threads).
pub fn file_parts<R: Read>(mut reader: R) -> io::Result<FileParts<R>> {
    let mut head = Vec::new();
    (&mut reader)
        .take(MIN_CHUNK_SIZE as u64 + 1)
        .read_to_end(&mut head)?;
    if head.len() <= MIN_CHUNK_SIZE {
        return Ok(FileParts::Whole((!head.is_empty()).then_some(head)));
    }
    Ok(FileParts::Stream(Box::new(StreamCDC::new(
        Cursor::new(head).chain(BufReader::with_capacity(1 << 20, reader)),
        MIN_CHUNK_SIZE,
        AVG_CHUNK_SIZE,
        MAX_CHUNK_SIZE,
    ))))
}

/// Chunk an in-memory buffer.
#[must_use]
pub fn chunk_bytes(bytes: &[u8]) -> Vec<Chunk> {
    match chunk_file(bytes) {
        Ok(chunks) => chunks.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
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
                (x & 0xff) as u8
            })
            .collect()
    }

    #[test]
    fn chunk_file_cuts_exactly_where_the_chunker_does() {
        // Around the one-chunk boundary and well past it: the same chunks, byte for byte, as
        // the chunker over the whole input.
        for len in [
            0,
            1,
            MIN_CHUNK_SIZE - 1,
            MIN_CHUNK_SIZE,
            MIN_CHUNK_SIZE + 1,
            MIN_CHUNK_SIZE * 2,
            9 * 1024 * 1024 + 13,
        ] {
            let data = pseudo_random(len, 11 + len as u64);
            let streamed: Vec<Chunk> = chunk_reader(&data[..]).map(Result::unwrap).collect();
            let filed: Vec<Chunk> = chunk_file(&data[..]).unwrap().map(Result::unwrap).collect();
            assert_eq!(filed, streamed, "length {len}");
        }
    }

    #[test]
    fn small_file_is_one_chunk_and_empty_is_none() {
        let data = b"hello world".to_vec();
        let chunks = chunk_bytes(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].data, data);
        assert_eq!(chunks[0].id, ChunkId::of(&data));
        assert!(chunk_bytes(&[]).is_empty());
    }

    #[test]
    fn chunk_sizes_respect_bounds_and_concatenate_back() {
        let data = pseudo_random(10 * 1024 * 1024, 7);
        let chunks = chunk_bytes(&data);
        assert!(chunks.len() > 2);
        for (i, c) in chunks.iter().enumerate() {
            assert!(c.data.len() <= MAX_CHUNK_SIZE);
            if i + 1 < chunks.len() {
                assert!(c.data.len() >= MIN_CHUNK_SIZE);
            }
        }
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.data.iter().copied()).collect();
        assert_eq!(joined, data);
    }

    #[test]
    fn append_only_changes_the_tail_chunk() {
        let mut data = pseudo_random(9_500_000, 11);
        let before = chunk_bytes(&data);
        data.extend_from_slice(&pseudo_random(6 * 1024, 99));
        let after = chunk_bytes(&data);
        let before_ids: std::collections::HashSet<_> = before.iter().map(|c| c.id).collect();
        let new: Vec<_> = after
            .iter()
            .filter(|c| !before_ids.contains(&c.id))
            .collect();
        assert!(
            new.len() <= 2,
            "expected at most two new chunks, got {}",
            new.len()
        );
    }

    #[test]
    fn chunk_id_round_trips_hex_and_serde() {
        let id = ChunkId::of(b"x");
        assert_eq!(ChunkId::parse(&id.to_hex()), Some(id));
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", id.to_hex()));
        let back: ChunkId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
        assert!(ChunkId::parse("zz").is_none());
    }
}
