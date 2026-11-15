//! The restore round trip as a rule over generated trees: whatever a worktree holds, capturing it
//! and restoring the head into an empty directory gives back the same tree. The same names
//! (bytes, not text), the same file bytes, the same mode bits and mtimes, the same symlink targets,
//! the same empty directories.
//!
//! The trees come from proptest, with a fixed seed so every run checks the same ones:
//! - names of plain letters, of arbitrary bytes (not UTF-8, spaces, newlines, quotes, a leading
//!   dash), of non-ASCII text and of up to 255 bytes (`NAME_MAX`). `.`, `..`, `.git*`, `HEAD`
//!   and `.sealantd` are left out: git, a nested repository and the daemon give those meaning of
//!   their own; so is `node_modules`, which holds the bulk tree;
//! - files empty, small, a few KiB, and now and then a few MiB of random bytes that the chunker
//!   cuts more than once;
//! - file and directory modes with the owner able to read (setuid and sticky among them), and
//!   mtimes to the nanosecond;
//! - symlinks to a sibling, up the tree, to an absolute path, to nothing, to arbitrary bytes;
//! - empty directories and directories holding only empty ones, three levels deep.
//!
//! Each case writes two trees: one into the worktree, captured in the workspace class (git's pack,
//! the raw tree and the metadata overlay), and one under `node_modules/`, captured in the bulk class
//! (content-defined chunks, packs and dir objects). The worktree tree is committed to git first in
//! half the cases, so both its tracked and untracked paths are exercised. A generated name may itself
//! be a bulk directory (`dist`, `build`, `target`): the class boundary then falls inside the tree.
//!
//! `CASES` cases per run: about 9 s on a debug build with 4 cores (24 cases, 15 Nov 2026).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use nix::sys::stat::{UtimensatFlags, utimensat};
use nix::sys::time::TimeSpec;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed, TestRunner};
use sealant_capture::{
    CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, SnapRequest,
};
use sealant_process::CommandGateExt;

/// Generated trees per run.
const CASES: u32 = 24;

/// A file's size: what the generator picks from.
fn size() -> impl Strategy<Value = usize> {
    prop_oneof![
        3 => Just(0usize),
        6 => 1usize..256,
        3 => 256usize..64 * 1024,
        // Past the chunker's 4 MiB cut: at least two chunks.
        1 => 4 * 1024 * 1024 + 1usize..5 * 1024 * 1024,
    ]
}

/// A name as bytes; shown as the OS string it is, escapes and all.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Name(Vec<u8>);

impl std::fmt::Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", OsStr::from_bytes(&self.0))
    }
}

#[derive(Clone)]
enum Node {
    File {
        size: usize,
        seed: u64,
        mode: u32,
        mtime: i64,
    },
    Link {
        target: Vec<u8>,
        mtime: i64,
    },
    Dir {
        mode: u32,
        mtime: i64,
        children: BTreeMap<Name, Node>,
    },
}

/// A shrunk case reads as a tree: each file's mode and size, each link's target.
impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File { size, mode, .. } => write!(f, "file {mode:o}, {size} bytes"),
            Self::Link { target, .. } => write!(f, "link -> {:?}", OsStr::from_bytes(target)),
            Self::Dir { mode, children, .. } => {
                write!(f, "dir {mode:o} ")?;
                f.debug_map().entries(children.iter()).finish()
            }
        }
    }
}

fn name() -> impl Strategy<Value = Name> {
    prop_oneof![
        3 => "[a-z0-9][a-z0-9._-]{0,11}".prop_map(String::into_bytes),
        3 => proptest::collection::vec(any::<u8>().prop_filter("no NUL or /", |b| *b != 0 && *b != b'/'), 1..24),
        1 => "[^/\u{0}]{1,8}".prop_map(String::into_bytes),
        1 => (200usize..=255).prop_map(|n| vec![b'n'; n]),
    ]
    .prop_filter("a name with no meaning of its own", |n| {
        n != b"."
            && n != b".."
            && n != b"HEAD"
            && n != b".sealantd"
            && n != b"node_modules"
            && !n.starts_with(b".git")
    })
    .prop_map(Name)
}

fn mtime() -> impl Strategy<Value = i64> {
    // 2001 to 2033, to the nanosecond.
    1_000_000_000_000_000_000i64..2_000_000_000_000_000_000
}

fn file() -> impl Strategy<Value = Node> {
    (
        size(),
        any::<u64>(),
        prop::sample::select(vec![
            0o644, 0o600, 0o640, 0o755, 0o750, 0o700, 0o444, 0o400, 0o4755,
        ]),
        mtime(),
    )
        .prop_map(|(size, seed, mode, mtime)| Node::File {
            size,
            seed,
            mode,
            mtime,
        })
}

fn link() -> impl Strategy<Value = Node> {
    (
        prop_oneof![
            name().prop_map(|n| n.0),
            name().prop_map(|n| [b"../".as_slice(), &n.0].concat()),
            Just(b"/nonexistent/target".to_vec()),
            proptest::collection::vec(any::<u8>().prop_filter("no NUL", |b| *b != 0), 1..64),
        ],
        mtime(),
    )
        .prop_map(|(target, mtime)| Node::Link { target, mtime })
}

fn tree() -> impl Strategy<Value = Node> {
    let leaf = prop_oneof![4 => file(), 1 => link()];
    leaf.prop_recursive(3, 24, 5, |inner| {
        (
            prop::sample::select(vec![0o755, 0o700, 0o750, 0o711, 0o775, 0o1777]),
            mtime(),
            proptest::collection::btree_map(name(), inner, 0..5),
        )
            .prop_map(|(mode, mtime, children)| Node::Dir {
                mode,
                mtime,
                children,
            })
    })
}

/// The top of the worktree: up to six entries.
fn top() -> impl Strategy<Value = BTreeMap<Name, Node>> {
    proptest::collection::btree_map(name(), tree(), 0..6)
}

/// `n` bytes from `seed`: random enough that the chunker cuts where content does.
fn bytes(n: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(n + 8);
    while out.len() < n {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(n);
    out
}

fn set_mtime(path: &Path, ns: i64) {
    let mtime = TimeSpec::new(ns / 1_000_000_000, ns % 1_000_000_000);
    utimensat(
        nix::fcntl::AT_FDCWD,
        path,
        &TimeSpec::UTIME_OMIT,
        &mtime,
        UtimensatFlags::NoFollowSymlink,
    )
    .unwrap();
}

/// Write the entries under `dir`: contents first, then each one's mode and mtime, a directory's
/// after its children.
fn write(dir: &Path, children: &BTreeMap<Name, Node>) {
    for (name, node) in children {
        let path = dir.join(OsStr::from_bytes(&name.0));
        match node {
            Node::File {
                size,
                seed,
                mode,
                mtime,
            } => {
                fs::write(&path, bytes(*size, *seed)).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(*mode)).unwrap();
                set_mtime(&path, *mtime);
            }
            Node::Link { target, mtime } => {
                std::os::unix::fs::symlink(OsStr::from_bytes(target), &path).unwrap();
                set_mtime(&path, *mtime);
            }
            Node::Dir {
                mode,
                mtime,
                children,
            } => {
                fs::create_dir(&path).unwrap();
                write(&path, children);
                fs::set_permissions(&path, fs::Permissions::from_mode(*mode)).unwrap();
                set_mtime(&path, *mtime);
            }
        }
    }
}

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .stdin(Stdio::null())
        .output_gated()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// One path as compared between two trees.
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    File {
        mode: u32,
        mtime: i64,
        bytes: Vec<u8>,
    },
    Link {
        mtime: i64,
        target: PathBuf,
    },
    Dir {
        mode: u32,
        mtime: i64,
    },
}

/// Every path under `root` but the root itself, `.git` and the daemon's directory, by its bytes.
fn snapshot(root: &Path) -> BTreeMap<Vec<u8>, Entry> {
    let mut out = BTreeMap::new();
    for e in walkdir::WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            e.depth() != 1 || (e.file_name() != ".git" && e.file_name() != ".sealantd")
        })
    {
        let e = e.unwrap();
        let rel = e
            .path()
            .strip_prefix(root)
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec();
        let meta = fs::symlink_metadata(e.path()).unwrap();
        let mtime = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
        let entry = if meta.is_symlink() {
            Entry::Link {
                mtime,
                target: fs::read_link(e.path()).unwrap(),
            }
        } else if meta.is_dir() {
            Entry::Dir {
                mode: meta.mode() & 0o7777,
                mtime,
            }
        } else {
            Entry::File {
                mode: meta.mode() & 0o7777,
                mtime,
                bytes: fs::read(e.path()).unwrap(),
            }
        };
        out.insert(rel, entry);
    }
    out
}

/// What differs between two snapshots, one line per path (a file's bytes by length only).
fn differences(a: &BTreeMap<Vec<u8>, Entry>, b: &BTreeMap<Vec<u8>, Entry>) -> Vec<String> {
    let brief = |e: Option<&Entry>| match e {
        Some(Entry::File { mode, mtime, bytes }) => {
            format!("file {mode:o} mtime {mtime} {} bytes", bytes.len())
        }
        other => format!("{other:?}"),
    };
    a.keys()
        .chain(b.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|k| a.get(*k) != b.get(*k))
        .map(|k| {
            format!(
                "{:?}: captured {} restored {}",
                OsStr::from_bytes(k),
                brief(a.get(k)),
                brief(b.get(k))
            )
        })
        .collect()
}

/// Write `top` into a fresh worktree (committed when `tracked`) and `bulk` under its
/// `node_modules/`, capture both classes, ship them, restore the head into an empty directory, and
/// say what differs.
fn round_trip(
    top: &BTreeMap<Name, Node>,
    bulk: &BTreeMap<Name, Node>,
    tracked: bool,
) -> Vec<String> {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    fs::write(root.join(".gitignore"), "/node_modules/\n").unwrap();
    write(&root, top);
    fs::create_dir(root.join("node_modules")).unwrap();
    write(&root.join("node_modules"), bulk);
    set_mtime(&root.join("node_modules"), 1_500_000_000_123_456_789);
    if tracked {
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "--allow-empty", "-m", "tree"]);
    }
    let before = snapshot(&root);

    let store = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt-prop", 1, None));
    let config = CaptureConfig::new("wt-prop", 1, &root);
    let bulk_dirs = config.bulk_dirs.clone();
    let mut engine = CaptureEngine::open(config, None).unwrap();
    for (seq, class) in [(1, Class::Small), (2, Class::Bulk)] {
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Checkpoint,
                class,
                seq,
            })
            .unwrap();
    }
    engine
        .shipper(store.clone(), registrar.clone())
        .ship_pending()
        .unwrap();
    let head = registrar.head().unwrap();

    let restored = tmp.path().join("restored");
    let mut targets = MaterializeTargets::new(&restored, None);
    targets.bulk_dirs = bulk_dirs;
    let materializer = Materializer::new(store.as_ref(), targets);
    let manifest = materializer
        .fetch_manifest(&head.manifest_key, &head.capture_id)
        .unwrap();
    materializer
        .materialize(&manifest.manifest, MaterializeClass::All)
        .unwrap();

    let mut diffs = differences(&before, &snapshot(&restored));
    let after = snapshot(&root);
    if after != before {
        diffs.insert(
            0,
            format!(
                "the capture changed the source: {:?}",
                differences(&before, &after)
            ),
        );
    }
    diffs
}

#[test]
fn capture_then_restore_gives_back_the_same_tree() {
    let config = Config {
        cases: CASES,
        rng_seed: RngSeed::Fixed(0x5EA1_A47D),
        failure_persistence: None,
        // A shrink step is a whole capture and restore: bound the search.
        max_shrink_iters: 200,
        ..Config::default()
    };
    let mut runner = TestRunner::new(config);
    let result = runner.run(&(top(), top(), any::<bool>()), |(top, bulk, tracked)| {
        let diffs = round_trip(&top, &bulk, tracked);
        prop_assert!(diffs.is_empty(), "tracked: {tracked}\n{}", diffs.join("\n"));
        Ok(())
    });
    if let Err(e) = result {
        panic!("{e}");
    }
}
