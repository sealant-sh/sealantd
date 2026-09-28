//! Dir objects (ADR-0015 amendment decision 5): a content-addressed JSON listing of one
//! directory, entries sorted by name, kinds `file | symlink | dir | hardlink-group`, keyed by the
//! sha256 of the canonical bytes.
//!
//! # Names that are not UTF-8
//!
//! A Unix file name (and a symlink's text) is bytes; JSON strings are Unicode. A `name` (and a
//! virtual path, and a symlink `target`) is a *key*: the bytes as UTF-8 when they are UTF-8 and
//! hold no character of the escape range `U+10FF80..=U+10FFFF`; otherwise every byte of an
//! invalid sequence, and every byte of an escape-range character, becomes the character
//! `U+10FF00 + byte` (those bytes are all ≥ `0x80`, so the result is always in the escape
//! range). The mapping is a bijection ([`key_of`] / [`bytes_of`]): distinct names never share a
//! key, and a key decodes to exactly the bytes it came from. An entry whose key was escaped also
//! carries the bytes themselves, hex, in `raw_name` (`raw_target` for a symlink's text), so a
//! reader need not know the escape: it takes `raw_name` when present and `name` otherwise. A
//! hardlink group's `target` is a virtual path, so a key: decode it with [`bytes_of`], or resolve
//! it component by component through the entries' `name`s. Every name that is UTF-8 without an
//! escape-range character (all of them, in practice) encodes exactly as before, so no existing
//! dir object changes digest and no section format changes; a reader that predates the fields
//! ignores them and lays the escaped key down as the name, as it laid down the lossy name before.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use serde::{Deserialize, Serialize};

use crate::chunk::{ChunkId, sha256_hex};

/// `U+10FF00`: an escaped byte `b` is the character `ESCAPE_BASE + b`.
const ESCAPE_BASE: u32 = 0x10_FF00;
/// The first character of the escape range (`ESCAPE_BASE + 0x80`).
const ESCAPE_FIRST: u32 = 0x10_FF80;

fn is_escape_char(c: char) -> bool {
    u32::from(c) >= ESCAPE_FIRST
}

fn escaped(b: u8) -> char {
    // `ESCAPE_BASE + b` for `b` in 0..=255 is below `char::MAX` and not a surrogate.
    char::from_u32(ESCAPE_BASE + u32::from(b)).unwrap_or(char::REPLACEMENT_CHARACTER)
}

/// The key of a name (or of any byte string holding no `/`-meaning of its own: a relative path
/// keys component by component, since `/` is ASCII and never escaped). See the module docs.
#[must_use]
pub fn key_of(bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(s) = std::str::from_utf8(bytes)
        && !s.chars().any(is_escape_char)
    {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(bytes.len() + 8);
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            if is_escape_char(c) {
                let mut buf = [0u8; 4];
                out.extend(c.encode_utf8(&mut buf).bytes().map(escaped));
            } else {
                out.push(c);
            }
        }
        out.extend(chunk.invalid().iter().copied().map(escaped));
    }
    Cow::Owned(out)
}

/// The key of an OS string.
#[must_use]
pub fn key_of_os(name: &OsStr) -> Cow<'_, str> {
    key_of(name.as_bytes())
}

/// The bytes a key stands for: the inverse of [`key_of`].
#[must_use]
pub fn bytes_of(key: &str) -> Cow<'_, [u8]> {
    if !key.chars().any(is_escape_char) {
        return Cow::Borrowed(key.as_bytes());
    }
    let mut out = Vec::with_capacity(key.len());
    for c in key.chars() {
        if is_escape_char(c) {
            // In the escape range, so `c - ESCAPE_BASE` is 0x80..=0xFF.
            out.push(u8::try_from(u32::from(c) - ESCAPE_BASE).unwrap_or(b'?'));
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    Cow::Owned(out)
}

/// The OS string a key stands for.
#[must_use]
pub fn os_of_key(key: &str) -> OsString {
    OsString::from_vec(bytes_of(key).into_owned())
}

/// `raw_name` / `raw_target` for a key: the hex of its bytes when the key was escaped.
fn raw_of(key: &str) -> Option<String> {
    key.chars()
        .any(is_escape_char)
        .then(|| hex::encode(bytes_of(key)))
}

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
    /// The name's bytes, hex, when `name` is an escaped key (the name is not UTF-8, or holds an
    /// escape-range character; see the module docs). A reader takes these over `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_name: Option<String>,
    /// A symlink's text as bytes, hex, when `target` is an escaped key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_target: Option<String>,
    /// The entry could not be read at this snap (permission denied, an I/O error): what it
    /// holds — content, size, mtime — is carried from the last read of it, and a directory
    /// entry so marked stands for a directory that could not be listed, holding what the last
    /// reads under it found. Only an automatic snap writes it; a `final` snap with anything
    /// unreadable fails instead (`index::UnreadableWork`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread: Option<bool>,
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
            raw_name: None,
            raw_target: None,
            unread: None,
        }
        .with_raw_name()
    }

    /// A symlink entry.
    #[must_use]
    pub fn symlink(
        name: impl Into<String>,
        mode: u32,
        mtime: i64,
        target: impl Into<String>,
    ) -> Self {
        let target = target.into();
        Self {
            name: name.into(),
            kind: EntryKind::Symlink,
            mode,
            size: 0,
            mtime,
            chunks: None,
            raw_target: raw_of(&target),
            target: Some(target),
            child: None,
            group: None,
            torn: None,
            raw_name: None,
            unread: None,
        }
        .with_raw_name()
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
            raw_name: None,
            raw_target: None,
            unread: None,
        }
        .with_raw_name()
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
            raw_name: None,
            raw_target: None,
            unread: None,
        }
        .with_raw_name()
    }

    fn with_raw_name(mut self) -> Self {
        self.raw_name = raw_of(&self.name);
        self
    }

    /// The name as it is on disk: `raw_name` when present and a valid single name (non-empty,
    /// no `/`, no NUL, not `.` or `..`), the decoded key otherwise.
    #[must_use]
    pub fn os_name(&self) -> OsString {
        self.raw_name
            .as_deref()
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| {
                !b.is_empty()
                    && !b.contains(&b'/')
                    && !b.contains(&0)
                    && b.as_slice() != b"."
                    && b.as_slice() != b".."
            })
            .map_or_else(|| os_of_key(&self.name), OsString::from_vec)
    }

    /// A symlink's text as it is on disk: `raw_target` when present (and free of NUL), the
    /// decoded `target` key otherwise; `None` without a target.
    #[must_use]
    pub fn os_target(&self) -> Option<OsString> {
        let target = self.target.as_deref()?;
        Some(
            self.raw_target
                .as_deref()
                .and_then(|h| hex::decode(h).ok())
                .filter(|b| !b.contains(&0))
                .map_or_else(|| os_of_key(target), OsString::from_vec),
        )
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
    use std::os::unix::ffi::OsStrExt;

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

    /// Keys are a bijection with byte strings: UTF-8 without escape-range characters is
    /// itself, everything else escapes byte by byte and decodes back exactly.
    #[test]
    fn keys_round_trip_any_bytes() {
        let cases: Vec<Vec<u8>> = vec![
            b"plain".to_vec(),
            "caf\u{e9}".as_bytes().to_vec(),
            b"caf\xe9".to_vec(),
            b"\xff\xfe/x".to_vec(),
            "esc\u{10FF80}".as_bytes().to_vec(),
            "\u{10FFFF}".as_bytes().to_vec(),
            vec![0xF4, 0x8F, 0xBE],
            (0x80u8..=0xFF).collect(),
        ];
        let mut seen = std::collections::HashSet::new();
        for bytes in &cases {
            let key = key_of(bytes).into_owned();
            assert_eq!(bytes_of(&key).as_ref(), bytes.as_slice(), "{key:?}");
            assert!(seen.insert(key.clone()), "{key:?} is not unique");
            let escaped = raw_of(&key).is_some();
            assert_eq!(
                escaped,
                std::str::from_utf8(bytes).map_or(true, |s| s.chars().any(is_escape_char)),
                "{bytes:?}"
            );
        }
        assert_eq!(key_of(b"plain"), "plain");
        let e = DirEntry::file(key_of(b"caf\xe9"), 0o644, 0, 0, vec![]);
        assert_eq!(e.raw_name.as_deref(), Some("636166e9"));
        assert_eq!(e.os_name().as_bytes(), b"caf\xe9");
        let json = String::from_utf8(DirObject::new(vec![e.clone()]).encode().bytes).unwrap();
        assert_eq!(DirObject::decode(json.as_bytes()).unwrap().entries[0], e);
        let bad = DirEntry {
            raw_name: Some(hex::encode(b"../x")),
            ..DirEntry::file("x", 0o644, 0, 0, vec![])
        };
        assert_eq!(
            bad.os_name().as_bytes(),
            b"x",
            "a raw name with a slash is refused"
        );
        assert!(
            !serde_json::to_string(&DirEntry::file("plain", 0o644, 0, 0, vec![]))
                .unwrap()
                .contains("raw_"),
            "a UTF-8 name encodes as before"
        );
    }
}
