//! Compare two snapshots into normalized `file.changed` events, with heuristic rename detection.

use sealant_protocol::{FileChange, FileChangeKind};

use crate::snapshot::Snapshot;

fn change(
    kind: FileChangeKind,
    path: String,
    entry: Option<sealant_protocol::FileEntry>,
) -> FileChange {
    FileChange {
        kind,
        path,
        rename_from: None,
        entry,
        certain: true,
    }
}

/// Compute the changes from `old` to `new`.
///
/// Modifications are detected by content hash (falling back to size); a deleted entry and an added
/// entry that share a non-empty content hash are reported as an *inferred* (`certain = false`)
/// rename. Per-process attribution is not available from snapshots alone (plan §13).
#[must_use]
pub fn diff(old: &Snapshot, new: &Snapshot) -> Vec<FileChange> {
    let mut changes = Vec::new();

    // Deleted / modified / metadata-changed.
    let mut deleted: Vec<sealant_protocol::FileEntry> = Vec::new();
    for (path, old_entry) in &old.entries {
        match new.entries.get(path) {
            None => deleted.push(old_entry.clone()),
            Some(new_entry) => {
                if old_entry.hash != new_entry.hash || old_entry.size != new_entry.size {
                    changes.push(change(
                        FileChangeKind::Modified,
                        path.clone(),
                        Some(new_entry.clone()),
                    ));
                } else if old_entry.mtime_micros != new_entry.mtime_micros
                    || old_entry.mode != new_entry.mode
                    || old_entry.symlink_target != new_entry.symlink_target
                {
                    changes.push(change(
                        FileChangeKind::MetadataChanged,
                        path.clone(),
                        Some(new_entry.clone()),
                    ));
                }
            }
        }
    }

    // Added entries (new, not in old).
    let added: Vec<sealant_protocol::FileEntry> = new
        .entries
        .iter()
        .filter(|(path, _)| !old.entries.contains_key(*path))
        .map(|(_, entry)| entry.clone())
        .collect();
    let mut added_used = vec![false; added.len()];

    // Match deletes to adds by content hash → inferred renames; otherwise emit deletes.
    for deleted_entry in &deleted {
        let matched = deleted_entry.hash.as_ref().and_then(|hash| {
            added.iter().enumerate().position(|(i, added_entry)| {
                !added_used[i] && added_entry.hash.as_ref() == Some(hash)
            })
        });
        if let Some(idx) = matched {
            added_used[idx] = true;
            changes.push(FileChange {
                kind: FileChangeKind::Renamed,
                path: added[idx].path.clone(),
                rename_from: Some(deleted_entry.path.clone()),
                entry: Some(added[idx].clone()),
                certain: false,
            });
        } else {
            changes.push(change(
                FileChangeKind::Deleted,
                deleted_entry.path.clone(),
                None,
            ));
        }
    }

    // Remaining adds (not consumed as rename targets).
    for (i, added_entry) in added.iter().enumerate() {
        if !added_used[i] {
            changes.push(change(
                FileChangeKind::Added,
                added_entry.path.clone(),
                Some(added_entry.clone()),
            ));
        }
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{SnapshotConfig, snapshot};
    use std::fs;

    fn snap(root: &std::path::Path) -> Snapshot {
        snapshot(root, &SnapshotConfig::default())
    }

    #[test]
    fn detects_add_modify_delete() {
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path();
        fs::write(root.join("keep.txt"), b"keep").expect("w");
        fs::write(root.join("gone.txt"), b"gone").expect("w");
        let before = snap(root);

        fs::write(root.join("keep.txt"), b"changed").expect("w"); // modify
        fs::remove_file(root.join("gone.txt")).expect("rm"); // delete
        fs::write(root.join("new.txt"), b"new").expect("w"); // add
        let after = snap(root);

        let changes = diff(&before, &after);
        let kinds: Vec<_> = changes.iter().map(|c| (c.kind, c.path.clone())).collect();
        assert!(kinds.contains(&(FileChangeKind::Modified, "keep.txt".to_owned())));
        assert!(kinds.contains(&(FileChangeKind::Deleted, "gone.txt".to_owned())));
        assert!(kinds.contains(&(FileChangeKind::Added, "new.txt".to_owned())));
    }

    #[test]
    fn detects_inferred_rename() {
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path();
        fs::write(root.join("old-name.txt"), b"unique-content-12345").expect("w");
        let before = snap(root);

        fs::rename(root.join("old-name.txt"), root.join("new-name.txt")).expect("mv");
        let after = snap(root);

        let renames: Vec<_> = diff(&before, &after)
            .into_iter()
            .filter(|c| c.kind == FileChangeKind::Renamed)
            .collect();
        assert_eq!(renames.len(), 1);
        assert_eq!(renames[0].rename_from.as_deref(), Some("old-name.txt"));
        assert_eq!(renames[0].path, "new-name.txt");
        assert!(!renames[0].certain, "snapshot rename is inferred");
    }
}
