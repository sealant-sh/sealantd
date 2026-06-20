//! Baseline/final filesystem snapshots: a path-bounded, symlink-safe walk capturing per-entry
//! metadata and optional content hashes.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::UNIX_EPOCH;

use sealant_protocol::{FileEntry, FileType};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

/// Directory names ignored by default (generated/VCS trees).
pub const DEFAULT_IGNORES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".sealantd",
    ".hg",
    ".svn",
    ".cache",
];

/// Snapshot configuration.
#[derive(Debug, Clone)]
pub struct SnapshotConfig {
    /// Directory names to skip entirely.
    pub ignores: Vec<String>,
    /// Hash regular files up to this size; larger files record size/mtime only.
    pub max_hash_bytes: u64,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            ignores: DEFAULT_IGNORES.iter().map(|s| (*s).to_owned()).collect(),
            max_hash_bytes: 4 * 1024 * 1024,
        }
    }
}

/// A point-in-time view of a workspace: relative path → entry metadata.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Entries keyed by path relative to the snapshot root.
    pub entries: BTreeMap<String, FileEntry>,
}

impl Snapshot {
    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the snapshot is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn file_type_of(ft: std::fs::FileType) -> FileType {
    if ft.is_file() {
        FileType::File
    } else if ft.is_dir() {
        FileType::Dir
    } else if ft.is_symlink() {
        FileType::Symlink
    } else {
        FileType::Other
    }
}

fn hash_file(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).ok()?;
    Some(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn is_ignored_dir(name: &str, ignores: &[String]) -> bool {
    ignores.iter().any(|i| i == name)
}

/// Whether a path's file name looks like an editor temp/save-probe file (coalesced away).
#[must_use]
pub fn is_temp_path(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name.ends_with('~')
        || name.ends_with(".swp")
        || name.ends_with(".swx")
        || name.ends_with(".swo")
        || name.ends_with(".tmp")
        || name.starts_with(".#")
        || (name.starts_with('#') && name.ends_with('#'))
        || name == "4913"
}

/// Snapshot `root`, skipping ignored directories, editor temp files, and never following symlinks.
#[must_use]
pub fn snapshot(root: &Path, config: &SnapshotConfig) -> Snapshot {
    let mut entries = BTreeMap::new();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            // Prune ignored directory subtrees (by name, below the root).
            let name = e.file_name().to_string_lossy();
            !(e.depth() > 0 && e.file_type().is_dir() && is_ignored_dir(&name, &config.ignores))
        });

    for entry in walker.flatten() {
        if entry.depth() == 0 {
            continue; // the root itself
        }
        let path = entry.path();
        let Ok(relative) = path.strip_prefix(root) else {
            continue; // path-escape guard
        };
        let rel = relative.to_string_lossy().to_string();
        if rel.is_empty() || is_temp_path(&rel) {
            continue;
        }
        // `metadata()` honors follow_links(false): a symlink stats as a symlink (no traversal).
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let file_type = file_type_of(meta.file_type());
        let mtime_micros = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_micros() as i64);
        let symlink_target = if matches!(file_type, FileType::Symlink) {
            std::fs::read_link(path)
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };
        let hash = if matches!(file_type, FileType::File) && meta.len() <= config.max_hash_bytes {
            hash_file(path)
        } else {
            None
        };

        entries.insert(
            rel.clone(),
            FileEntry {
                path: rel,
                file_type,
                size: meta.len(),
                mtime_micros,
                mode: meta.permissions().mode(),
                hash,
                symlink_target,
            },
        );
    }

    Snapshot { entries }
}

/// Stat a single path into a [`FileEntry`] relative to `root` (lstat; symlinks not followed).
/// Returns `None` if the path is gone or escapes the root.
#[must_use]
pub fn entry_for(root: &Path, path: &Path, max_hash_bytes: u64) -> Option<FileEntry> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let rel = path.strip_prefix(root).ok()?.to_string_lossy().to_string();
    if rel.is_empty() {
        return None;
    }
    let file_type = file_type_of(meta.file_type());
    let mtime_micros = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_micros() as i64);
    let symlink_target = if matches!(file_type, FileType::Symlink) {
        std::fs::read_link(path)
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    } else {
        None
    };
    let hash = if matches!(file_type, FileType::File) && meta.len() <= max_hash_bytes {
        hash_file(path)
    } else {
        None
    };
    Some(FileEntry {
        path: rel,
        file_type,
        size: meta.len(),
        mtime_micros,
        mode: meta.permissions().mode(),
        hash,
        symlink_target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn snapshots_files_and_skips_ignored_and_temp() {
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path();
        fs::write(root.join("a.txt"), b"hello").expect("write");
        fs::create_dir_all(root.join("sub")).expect("mkdir");
        fs::write(root.join("sub/b.txt"), b"world").expect("write");
        fs::create_dir_all(root.join("node_modules/pkg")).expect("mkdir");
        fs::write(root.join("node_modules/pkg/index.js"), b"ignored").expect("write");
        fs::write(root.join("a.txt~"), b"editor temp").expect("write");

        let snap = snapshot(root, &SnapshotConfig::default());
        assert!(snap.entries.contains_key("a.txt"));
        assert!(snap.entries.contains_key("sub/b.txt"));
        assert!(snap.entries.contains_key("sub"));
        // node_modules pruned; temp file skipped.
        assert!(!snap.entries.keys().any(|k| k.starts_with("node_modules")));
        assert!(!snap.entries.contains_key("a.txt~"));
        let a = &snap.entries["a.txt"];
        assert_eq!(a.size, 5);
        assert!(a.hash.as_ref().is_some_and(|h| h.starts_with("sha256:")));
    }

    #[test]
    fn symlinks_are_recorded_not_followed() {
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path();
        fs::write(root.join("real.txt"), b"x").expect("write");
        std::os::unix::fs::symlink("real.txt", root.join("link.txt")).expect("symlink");
        // A symlink loop must not hang the walk.
        std::os::unix::fs::symlink(".", root.join("loop")).expect("symlink loop");

        let snap = snapshot(root, &SnapshotConfig::default());
        let link = &snap.entries["link.txt"];
        assert_eq!(link.file_type, FileType::Symlink);
        assert_eq!(link.symlink_target.as_deref(), Some("real.txt"));
        assert_eq!(snap.entries["loop"].file_type, FileType::Symlink);
    }
}
