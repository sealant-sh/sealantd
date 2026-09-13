//! Dir objects (ADR-0015 amendment decision 5): a content-addressed JSON listing of one
//! directory, entries sorted by name, kinds `file | symlink | dir | hardlink-group`, keyed by the
//! sha256 of the canonical bytes.

use serde::{Deserialize, Serialize};

use crate::chunk::{ChunkId, sha256_hex};

/// Entry kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryKind {
    /// Regular file: `chunks` lists its content.
    File,
    /// Symbolic link: `target` is the link text, never followed.
    Symlink,
    /// Directory: `child` is the dir object key.
    Dir,
    /// Another name of a file already listed: `target` is the group's canonical path (its first
    /// member in path order, relative to the class root); no chunks.
    HardlinkGroup,
}

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// File name within the directory.
    pub name: String,
    /// Kind.
    pub kind: EntryKind,
    /// `st_mode` permission bits.
    pub mode: u32,
    /// Size in bytes (0 for dirs).
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime: i64,
    /// Content chunks, in order (files only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunks: Option<Vec<ChunkId>>,
    /// Symlink text, or a hardlink group's canonical path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Child dir object key (dirs only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child: Option<String>,
    /// File group read together (SQLite `db` + `-wal`): the group's base file name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The file (or its group) changed underneath the reader on every attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub torn: Option<bool>,
}

impl DirEntry {
    /// A file entry.
    #[must_use]
    pub fn file(
        name: impl Into<String>,
        mode: u32,
        size: u64,
        mtime: i64,
        chunks: Vec<ChunkId>,
    ) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::File,
            mode,
            size,
            mtime,
            chunks: Some(chunks),
            target: None,
            child: None,
            group: None,
            torn: None,
        }
    }

    /// A symlink entry.
    #[must_use]
    pub fn symlink(
        name: impl Into<String>,
        mode: u32,
        mtime: i64,
        target: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::Symlink,
            mode,
            size: 0,
            mtime,
            chunks: None,
            target: Some(target.into()),
            child: None,
            group: None,
            torn: None,
        }
    }

    /// A directory entry.
    #[must_use]
    pub fn dir(
        name: impl Into<String>,
        mode: u32,
        mtime: i64,
        child_key: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::Dir,
            mode,
            size: 0,
            mtime,
            chunks: None,
            target: None,
            child: Some(child_key.into()),
            group: None,
            torn: None,
        }
    }

    /// A hardlink-group member pointing at the group's canonical path.
    #[must_use]
    pub fn hardlink(
        name: impl Into<String>,
        mode: u32,
        size: u64,
        mtime: i64,
        canonical: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::HardlinkGroup,
            mode,
            size,
            mtime,
            chunks: None,
            target: Some(canonical.into()),
            child: None,
            group: None,
            torn: None,
        }
    }
}

/// A dir object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirObject {
    /// Entries, sorted by name.
    pub entries: Vec<DirEntry>,
}

/// An encoded dir object: canonical bytes and their sha256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedDir {
    /// Canonical JSON.
    pub bytes: Vec<u8>,
    /// Lowercase hex sha256 of `bytes`.
    pub sha256: String,
}

impl DirObject {
    /// Build from entries in any order.
    #[must_use]
    pub fn new(mut entries: Vec<DirEntry>) -> Self {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Self { entries }
    }

    /// Canonical bytes (sorted entries, fixed field order, compact JSON) and their digest.
    #[must_use]
    pub fn encode(&self) -> EncodedDir {
        let sorted = Self::new(self.entries.clone());
        // Serializing a struct cannot fail.
        let bytes = serde_json::to_vec(&sorted).unwrap_or_default();
        let sha256 = sha256_hex(&bytes);
        EncodedDir { bytes, sha256 }
    }

    /// Decode from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_is_canonical_and_kinds_are_kebab() {
        let a = DirObject::new(vec![
            DirEntry::file("b", 0o644, 3, 10, vec![ChunkId::of(b"abc")]),
            DirEntry::symlink("a", 0o777, 11, "b"),
        ]);
        let b = DirObject::new(vec![
            DirEntry::symlink("a", 0o777, 11, "b"),
            DirEntry::file("b", 0o644, 3, 10, vec![ChunkId::of(b"abc")]),
        ]);
        assert_eq!(a.encode(), b.encode());
        let json = String::from_utf8(a.encode().bytes).unwrap();
        assert!(json.contains("\"kind\":\"symlink\""));
        assert!(!json.contains("\"child\""));
        let back = DirObject::decode(json.as_bytes()).unwrap();
        assert_eq!(back, a);
        let hl = DirEntry::hardlink("c", 0o644, 3, 10, "x/b");
        assert_eq!(
            serde_json::to_string(&hl.kind).unwrap(),
            "\"hardlink-group\""
        );
    }
}
