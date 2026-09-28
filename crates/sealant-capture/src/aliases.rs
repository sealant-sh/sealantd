//! Files with more than one name (hardlinks), for the cadence (review 2026-09-28, sixth pass,
//! #2). The watcher watches directories, and a write through one name of an inode is an event
//! on that name's directory only: a write through a bulk-class name of a tracked file dirtied
//! the bulk class and never the small one, and a write through a name outside the workspace
//! (a file linked into `/tmp`, a package store) dirtied nothing. Either way the class that held
//! the old bytes was never snapped again, however many capture intervals passed.
//!
//! [`Aliases`] holds every multi-link regular file each class's last snap read, by inode:
//!
//! - an event on one name of an inode names every other name the classes hold
//!   ([`Aliases::others`]): the watcher dirties every class that owns one, and notes each
//!   name for its class's next build;
//! - an inode whose names are in both classes, or that has names neither class holds (its link
//!   count is more than the names the snaps saw), is stat'ed on the class's maximum interval
//!   ([`Aliases::poll`]): a write through a name no watch sees moves the inode's size, mtime or
//!   ctime, and every class owning a name is dirtied then.
//!
//! A write through any name is thus seen within the class's maximum interval. The cadence's
//! reconcile interval ([`crate::engine::Cadence::reconcile`]) bounds whatever this misses.

use std::collections::HashMap;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::engine::Class;
use crate::index::FileStat;
use crate::longpath;

/// A stat recorded within this many nanoseconds of a change is not trusted to show the next
/// one (a write in the same timestamp tick leaves it as it was): the inode is stat'ed as
/// changed at the next poll, once.
const RACY_NS: i64 = 2_000_000_000;

/// One name of a multi-link regular file, as a snap read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedName {
    /// The name, absolute.
    pub path: PathBuf,
    /// Its stat when the snap read it.
    pub stat: FileStat,
    /// Its link count then.
    pub nlink: u64,
}

impl LinkedName {
    /// `path` when `meta` is a regular file with more than one name.
    #[must_use]
    pub fn of(path: &Path, meta: &Metadata) -> Option<Self> {
        (meta.is_file() && meta.nlink() > 1).then(|| Self {
            path: path.to_path_buf(),
            stat: FileStat::of(meta),
            nlink: meta.nlink(),
        })
    }
}

/// An inode to stat: its key, its names, the stat last seen.
type Polled = ((u64, u64), Vec<(Class, PathBuf)>, Option<FileStat>);

/// An inode and the names the classes hold of it.
#[derive(Debug, Clone)]
struct Inode {
    names: Vec<(Class, PathBuf)>,
    /// The stat last seen; `None` when it cannot be trusted to show the next write.
    stat: Option<FileStat>,
    /// Its names are in both classes, or it has names neither class holds.
    polled: bool,
}

#[derive(Debug, Default)]
struct Table {
    /// Each class's names, as its last snap read them: small, bulk.
    names: [Vec<LinkedName>; 2],
    by_path: HashMap<PathBuf, (u64, u64)>,
    inodes: HashMap<(u64, u64), Inode>,
}

/// The multi-link files of both classes ([`crate::aliases`]).
#[derive(Debug, Default)]
pub struct Aliases {
    table: Mutex<Table>,
}

fn slot(class: Class) -> usize {
    usize::from(class == Class::Bulk)
}

fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

/// Whether two stats of one inode say the same bytes: a write moves the size, the mtime or the
/// ctime; a name that now names another inode moves the inode number.
fn same(a: &FileStat, b: &FileStat) -> bool {
    a.size == b.size && a.mtime == b.mtime && a.ctime == b.ctime && a.ino == b.ino && a.dev == b.dev
}

impl Aliases {
    /// The names `class`'s last successful snap read, replacing the ones before.
    pub fn record(&self, class: Class, names: Vec<LinkedName>) {
        let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        table.names[slot(class)] = names;
        let now = now_ns();
        let mut inodes: HashMap<(u64, u64), (Inode, u64)> = HashMap::new();
        // The other class's names first: this class's stats are the newer ones.
        for class in [class.other(), class] {
            for name in &table.names[slot(class)] {
                let key = (name.stat.dev, name.stat.ino);
                let racy = now.saturating_sub(name.stat.ctime.max(name.stat.mtime)) < RACY_NS;
                let (inode, nlink) = inodes.entry(key).or_insert_with(|| {
                    (
                        Inode {
                            names: Vec::new(),
                            stat: None,
                            polled: false,
                        },
                        0,
                    )
                });
                inode.names.push((class, name.path.clone()));
                inode.stat = (!racy).then_some(name.stat);
                *nlink = (*nlink).max(name.nlink);
            }
        }
        table.by_path.clear();
        table.inodes = inodes
            .into_iter()
            .map(|(key, (mut inode, nlink))| {
                inode.names.sort();
                inode.names.dedup();
                let cross = inode.names.iter().any(|(c, _)| *c == Class::Small)
                    && inode.names.iter().any(|(c, _)| *c == Class::Bulk);
                inode.polled = cross || nlink > inode.names.len() as u64;
                (key, inode)
            })
            .collect();
        let by_path: HashMap<PathBuf, (u64, u64)> = table
            .inodes
            .iter()
            .flat_map(|(key, inode)| inode.names.iter().map(move |(_, p)| (p.clone(), *key)))
            .collect();
        table.by_path = by_path;
    }

    /// Every other name the classes hold of the inode `path` named at their last snaps, with
    /// its class; empty for a path that is not one of them.
    #[must_use]
    pub fn others(&self, path: &Path) -> Vec<(Class, PathBuf)> {
        let table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(key) = table.by_path.get(path) else {
            return Vec::new();
        };
        table.inodes.get(key).map_or_else(Vec::new, |inode| {
            inode
                .names
                .iter()
                .filter(|(_, p)| p != path)
                .cloned()
                .collect()
        })
    }

    /// Stat every polled inode with a name in a class `due` selects (small, bulk): one name
    /// each, the next when that one is gone. Returns every name of each inode whose stat moved
    /// since the snaps read it (or since the last poll saw it move), with its class; one whose
    /// names are all gone counts as moved. What it sees is kept, so a change is reported once.
    #[must_use]
    pub fn poll(&self, due: [bool; 2]) -> Vec<(Class, PathBuf)> {
        let polled: Vec<Polled> = {
            let table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
            table
                .inodes
                .iter()
                .filter(|(_, inode)| inode.polled && inode.names.iter().any(|(c, _)| due[slot(*c)]))
                .map(|(key, inode)| (*key, inode.names.clone(), inode.stat))
                .collect()
        };
        let mut moved = Vec::new();
        let mut seen: Vec<((u64, u64), Option<FileStat>)> = Vec::new();
        for (key, names, stat) in polled {
            // Stat'ed outside the lock: a class's snap records meanwhile.
            let now = names
                .iter()
                .find_map(|(_, p)| longpath::symlink_metadata(p).ok())
                .filter(Metadata::is_file)
                .map(|m| FileStat::of(&m));
            let unchanged = matches!((&stat, &now), (Some(a), Some(b)) if same(a, b));
            if !unchanged {
                moved.extend(names);
                seen.push((key, now));
            }
        }
        if !seen.is_empty() {
            let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
            let at = now_ns();
            for (key, now) in seen {
                if let Some(inode) = table.inodes.get_mut(&key) {
                    inode.stat = now.filter(|s| at.saturating_sub(s.ctime.max(s.mtime)) >= RACY_NS);
                }
            }
        }
        moved
    }

    /// How many inodes are polled (test and log observability).
    #[must_use]
    pub fn polled(&self) -> usize {
        self.table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .inodes
            .values()
            .filter(|i| i.polled)
            .count()
    }
}
