//! What a sealed final flush holds is the disk, and nothing the capture runs changes it (review
//! 2026-09-28, fifth pass): no filter driver or hook of the user's runs in a capture's git (#2);
//! a regular file where the tree had a symlink is a regular file whatever `core.symlinks` says
//! (#6); a hardlink the overlay records across classes names only members the captures hold as
//! they are, and a sealed full restore that cannot make one says so (#11).

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use sealant_capture::manifest::WorktreeMeta;
use sealant_capture::materialize::MaterializeError;
use sealant_capture::pack::PackReader;
use sealant_capture::worktree_meta::{MetaDocument, MetaError};
use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, SnapRequest,
};

const EXECUTOR: &str = "exec-r5";

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

struct Fixture {
    tmp: tempfile::TempDir,
    root: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    fn new(ignore: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("a"), b"base\n").unwrap();
        fs::write(root.join(".gitignore"), ignore).unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "base"]);
        Self {
            store: Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap()),
            registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None).with_executor(EXECUTOR)),
            root,
            tmp,
        }
    }

    fn engine(&self) -> CaptureEngine {
        let mut config = CaptureConfig::new("wt", 1, &self.root);
        config.executor = Some(EXECUTOR.to_owned());
        CaptureEngine::open(config, None).unwrap()
    }

    /// A final flush that must say `complete` and seal the chain.
    fn final_flush(&self, engine: CaptureEngine) {
        let shipper = Arc::new(engine.shipper(self.store.clone(), self.registrar.clone()));
        let result = CadenceRunner::new(engine, shipper).flush_final(None);
        assert!(result.complete(), "{result:?}");
        let head = self.registrar.head().unwrap();
        assert!(head.manifest.final_seal.is_some(), "the chain is sealed");
    }

    fn restore(&self, name: &str) -> PathBuf {
        let out = self.tmp.path().join(name);
        Materializer::new(self.store.as_ref(), MaterializeTargets::new(&out, None))
            .materialize(
                &self.registrar.head().unwrap().manifest,
                MaterializeClass::All,
            )
            .unwrap();
        out
    }
}

fn read_doc(restored: &Path, meta: &WorktreeMeta) -> MetaDocument {
    let cache = restored.join(".sealantd/capture/cache");
    let mut bytes = Vec::new();
    for id in &meta.chunks {
        let found = meta.packs.iter().find_map(|p| {
            let reader = PackReader::open(&cache.join(p.rsplit('/').next().unwrap())).unwrap();
            reader.read(id).unwrap()
        });
        bytes.extend(found.expect("chunk in the overlay's packs"));
    }
    MetaDocument::decode(&bytes).unwrap()
}

/// #2: a clean filter, a long-running (`process`) filter and a `post-index-change` hook are the
/// user's code; a capture's `git add` ran every one of them, and a filter that wrote a file git
/// had already indexed changed the disk under a final flush that went on to seal it. None runs
/// now: the files their attributes name are read as they are on disk, the flush completes and
/// seals, and a restore holds the disk's bytes.
#[test]
fn no_filter_or_hook_of_the_user_runs_in_a_capture() {
    let fx = Fixture::new("");
    let marks = fx.tmp.path().join("marks");
    fs::create_dir_all(&marks).unwrap();
    let clean = marks.join("clean-ran");
    let process = marks.join("process-ran");
    let hook = marks.join("hook-ran");
    fs::write(
        fx.root.join(".gitattributes"),
        b"*.dat filter=mark\n*.bin filter=proc\n",
    )
    .unwrap();
    git(
        &fx.root,
        &[
            "config",
            "filter.mark.clean",
            &format!("touch {}; tr a-z A-Z", clean.display()),
        ],
    );
    git(&fx.root, &["config", "filter.mark.required", "true"]);
    git(
        &fx.root,
        &[
            "config",
            "filter.proc.process",
            &format!("sh -c 'touch {}'", process.display()),
        ],
    );
    git(&fx.root, &["config", "filter.proc.required", "true"]);
    let hooks = fx.root.join(".git/hooks");
    fs::create_dir_all(&hooks).unwrap();
    let hook_file = hooks.join("post-index-change");
    fs::write(&hook_file, format!("#!/bin/sh\ntouch {}\n", hook.display())).unwrap();
    fs::set_permissions(&hook_file, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(fx.root.join("notes.dat"), b"lower case work\n").unwrap();
    fs::write(fx.root.join("blob.bin"), b"\x00binary work\x01").unwrap();

    fx.final_flush(fx.engine());
    for mark in [&clean, &process, &hook] {
        assert!(!mark.exists(), "{} ran in a capture", mark.display());
    }
    let restored = fx.restore("restored");
    assert_eq!(
        fs::read(restored.join("notes.dat")).unwrap(),
        b"lower case work\n"
    );
    assert_eq!(
        fs::read(restored.join("blob.bin")).unwrap(),
        b"\x00binary work\x01"
    );
    assert_eq!(
        fs::read(fx.root.join("notes.dat")).unwrap(),
        b"lower case work\n"
    );
}

/// #6: `core.symlinks=false` (a setting carried from a file system without symlinks) made the
/// capture's `git add` keep a tracked symlink's mode over the regular file that replaced it,
/// its bytes taken for the link's target; the overlay dropped the path in silence and a sealed
/// final flush restored the file as a symlink. The capture's git sees symlinks as symlinks.
#[test]
fn symlinks_false_real_file_restores_as_a_file() {
    let fx = Fixture::new("");
    std::os::unix::fs::symlink("a", fx.root.join("link")).unwrap();
    git(&fx.root, &["add", "link"]);
    git(&fx.root, &["commit", "-qm", "a link"]);
    git(&fx.root, &["config", "core.symlinks", "false"]);
    fs::remove_file(fx.root.join("link")).unwrap();
    fs::write(fx.root.join("link"), b"unique regular file work\n").unwrap();
    fx.final_flush(fx.engine());
    let restored = fx.restore("restored");
    let meta = fs::symlink_metadata(restored.join("link")).unwrap();
    assert!(meta.is_file(), "a regular file restores as one: {meta:?}");
    assert_eq!(
        fs::read(restored.join("link")).unwrap(),
        b"unique regular file work\n"
    );
    // And the other way: a symlink where the tree has a file stays a symlink.
    let fx = Fixture::new("");
    git(&fx.root, &["config", "core.symlinks", "false"]);
    fs::remove_file(fx.root.join("a")).unwrap();
    std::os::unix::fs::symlink("elsewhere", fx.root.join("a")).unwrap();
    fx.final_flush(fx.engine());
    let restored = fx.restore("restored");
    assert_eq!(
        fs::read_link(restored.join("a")).unwrap(),
        Path::new("elsewhere")
    );
}

/// `core.fileMode=false` keeps the index's mode in the worktree tree; the overlay carries the
/// disk's mode bits all the same, so an executable bit set on the executor comes back.
#[test]
fn filemode_false_exec_bit_comes_back() {
    let fx = Fixture::new("");
    git(&fx.root, &["config", "core.fileMode", "false"]);
    fs::set_permissions(fx.root.join("a"), fs::Permissions::from_mode(0o755)).unwrap();
    fx.final_flush(fx.engine());
    let restored = fx.restore("restored");
    assert_eq!(
        fs::metadata(restored.join("a")).unwrap().mode() & 0o7777,
        0o755
    );
}

/// An ignored file (the workspace class) hardlinked to a file under `node_modules` (the bulk
/// class), with the last bulk snap before its bytes changed.
fn stale_bulk_link() -> (Fixture, CaptureEngine) {
    let fx = Fixture::new("ignored/\nnode_modules/\n");
    fs::create_dir_all(fx.root.join("ignored")).unwrap();
    fs::create_dir_all(fx.root.join("node_modules/p")).unwrap();
    fs::write(fx.root.join("ignored/x"), b"first bytes\n").unwrap();
    fs::hard_link(fx.root.join("ignored/x"), fx.root.join("node_modules/p/x")).unwrap();
    let mut engine = fx.engine();
    for (seq, class) in [(0, Class::Bulk), (1, Class::Small)] {
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Auto,
                class,
                seq,
            })
            .unwrap();
    }
    engine
        .shipper(fx.store.clone(), fx.registrar.clone())
        .flush(std::time::Duration::from_secs(10))
        .unwrap();
    let head = fx.registrar.head().unwrap();
    let restored = fx.restore("linked");
    let doc = read_doc(
        &restored,
        head.manifest
            .sections
            .workspace
            .worktree_meta
            .as_ref()
            .unwrap(),
    );
    assert_eq!(
        doc.cross_links.len(),
        1,
        "captured together, the two names are one link: {:?}",
        doc.cross_links
    );
    // Written in place through the workspace name: one inode, new bytes under both names; the
    // bulk capture still holds the first ones.
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(
        fx.root.join("ignored/x"),
        b"second bytes, not in the bulk capture\n",
    )
    .unwrap();
    (fx, engine)
}

/// #11, the writer: a small snap after the linked file changed recorded the cross-class link
/// from the bulk index as the last bulk snap left it, though the bulk capture held other
/// bytes: a link the captures cannot give back. It names only members the captures hold as
/// they are; a final flush snaps the bulk class and records it then, one inode on restore.
#[test]
fn a_cross_class_link_names_only_members_captured_as_they_are() {
    let (fx, mut engine) = stale_bulk_link();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 2,
        })
        .unwrap();
    engine
        .shipper(fx.store.clone(), fx.registrar.clone())
        .flush(std::time::Duration::from_secs(10))
        .unwrap();
    let head = fx.registrar.head().unwrap();
    let restored = fx.restore("auto");
    let doc = read_doc(
        &restored,
        head.manifest
            .sections
            .workspace
            .worktree_meta
            .as_ref()
            .unwrap(),
    );
    let named: Vec<&str> = doc
        .cross_links
        .iter()
        .flatten()
        .map(|m| m.member.as_str())
        .collect();
    assert!(
        !named.contains(&"node_modules/p/x"),
        "a bulk member whose capture holds other bytes is never linked: {named:?}"
    );

    fx.final_flush(engine);
    let restored = fx.restore("final");
    assert_eq!(
        fs::metadata(restored.join("ignored/x")).unwrap().ino(),
        fs::metadata(restored.join("node_modules/p/x"))
            .unwrap()
            .ino(),
        "one inode, as on disk"
    );
    assert_eq!(
        fs::read(restored.join("node_modules/p/x")).unwrap(),
        b"second bytes, not in the bulk capture\n"
    );
}

/// #11, the reader: a sealed final capture whose cross-class link cannot be made on restore (its
/// bulk section here is an older one, whose member holds other bytes) failed nothing: the
/// materialize passed and left two inodes. A sealed full restore now says the link is not
/// restorable, and writes neither file over the other.
#[test]
fn a_sealed_restore_surfaces_a_link_it_cannot_make() {
    let (fx, engine) = stale_bulk_link();
    let old_bulk = fx.registrar.head().unwrap().manifest.sections.bulk.clone();
    fx.final_flush(engine);
    let mut manifest = fx.registrar.head().unwrap().manifest;
    assert!(manifest.final_seal.is_some());
    manifest.sections.bulk = old_bulk;
    let out = fx.tmp.path().join("tampered");
    let result = Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&out, None))
        .materialize(&manifest, MaterializeClass::All);
    match result {
        Err(MaterializeError::WorktreeMeta(MetaError::LinkUnfulfilled { member, .. })) => {
            assert_eq!(member, "node_modules/p/x");
        }
        other => panic!("a link the restore cannot make passed: {other:?}"),
    }
    assert_eq!(
        fs::read(out.join("node_modules/p/x")).unwrap(),
        b"first bytes\n",
        "neither file is written over"
    );
    assert_eq!(
        fs::read(out.join("ignored/x")).unwrap(),
        b"second bytes, not in the bulk capture\n"
    );
    // The same capture without its seal (an automatic one's promise) restores as before.
    manifest.final_seal = None;
    Materializer::new(
        fx.store.as_ref(),
        MaterializeTargets::new(&fx.tmp.path().join("unsealed"), None),
    )
    .materialize(&manifest, MaterializeClass::All)
    .unwrap();
}
