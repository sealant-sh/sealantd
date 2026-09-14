//! Tracked always wins, and a materialized executor's first packs carry everything the chain
//! lacks. The shape of the first real cluster session: the control plane authors capture 0
//! from a bare repository (one project pack, the commit tree as both pseudo-refs, an EMPTY
//! workspace class), an executor materializes it, edits, snaps, and a replacement executor —
//! or Mend's runner — must be able to read every tree the new manifest names.
//!
//! Observed before the fix: `D tooling/typescript/core.json` (a tracked file matching the
//! `.gitignore` line `core.*`) in the change view, and `fatal: unable to read tree` on the
//! next capture's root tree, whose new subtrees and index tree no pack of the chain held.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use sealant_capture::gitpack::{self, GitRepo};
use sealant_capture::keys::KeyPrefix;
use sealant_capture::manifest::{
    BulkState, CaptureKind, EncodedManifest, FsckStatus, GitSection, INDEX_TREE_REF, Manifest,
    Sections, WORKTREE_TREE_REF, WorkspaceSection,
};
use sealant_capture::registrar::{RegisterRequest, Registrar};
use sealant_capture::sink::{BlobSink, BlobSource};
use sealant_capture::tree::DirObject;
use sealant_capture::{
    CaptureConfig, CaptureEngine, Class, InMemoryRegistrar, LocalDir, MaterializeClass,
    MaterializeTargets, Materializer, SnapRequest,
};

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

fn git_ok(root: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// `git status --porcelain` without the daemon directory.
fn status(root: &Path) -> String {
    git(root, &["status", "--porcelain"])
        .lines()
        .filter(|l| !l.ends_with(".sealantd/"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every object reachable from `tips` in `root`.
fn objects_from(root: &Path, tips: &[String]) -> BTreeSet<String> {
    let mut args = vec!["rev-list", "--objects", "--no-object-names"];
    args.extend(tips.iter().map(String::as_str));
    git(root, &args).lines().map(str::to_owned).collect()
}

/// The source repository: `.gitignore` says `core.*` (core dumps), yet `tooling/core.json` is
/// tracked, as in the Mend repository.
fn source(base: &Path) -> GitRepo {
    let src = base.join("src");
    fs::create_dir_all(src.join("tooling")).unwrap();
    git(&src, &["init", "-q", "-b", "main"]);
    git(&src, &["config", "user.email", "t@t"]);
    git(&src, &["config", "user.name", "t"]);
    fs::write(src.join(".gitignore"), "core.*\n").unwrap();
    fs::write(src.join("a.txt"), "one\n").unwrap();
    fs::write(src.join("tooling/core.json"), "{\"strict\":true}\n").unwrap();
    git(&src, &["add", "-A"]);
    git(&src, &["add", "-f", "tooling/core.json"]);
    git(&src, &["commit", "-q", "-m", "one"]);
    assert!(
        git(&src, &["ls-files"]).contains("tooling/core.json"),
        "the fixture tracks the ignore-matching file"
    );
    GitRepo::open(&src).unwrap()
}

/// Capture 0 as the control plane writes it: the project's pack under `projects/…`, the
/// commit tree as both pseudo-refs, an empty workspace root, bulk pending; registered as the
/// head of `registrar`.
fn control_plane_base(
    base: &Path,
    src: &GitRepo,
    sink: &LocalDir,
    registrar: &InMemoryRegistrar,
) -> EncodedManifest {
    let scratch = base.join("cp-scratch");
    let packed = gitpack::build_git_pack(src, &scratch, &[], &[]).unwrap();
    let pack = packed.pack.expect("the project pack");
    let head_sha = git(&src.root, &["rev-parse", "HEAD"]);
    let head_tree = git(&src.root, &["rev-parse", "HEAD^{tree}"]);
    assert_eq!(packed.closure.refs[WORKTREE_TREE_REF], head_tree);
    let pack_key = format!("projects/p1/packs/{}", pack.sha256);
    sink.put_if_absent(&pack_key, BlobSource::File(&pack.path))
        .unwrap();
    sink.put_if_absent(&format!("{pack_key}.idx"), BlobSource::File(&pack.idx_path))
        .unwrap();
    let keys = KeyPrefix {
        worktree_id: "wt".into(),
        epoch: 1,
    };
    let empty = DirObject::default().encode();
    let root_key = keys.tree(&empty.sha256);
    sink.put_if_absent(&root_key, BlobSource::Bytes(&empty.bytes))
        .unwrap();
    let manifest = Manifest {
        worktree_id: "wt".into(),
        n: 0,
        parent: None,
        epoch: 1,
        seq: 0,
        kind: CaptureKind::Checkpoint,
        created_at: "2026-09-14T10:18:16Z".into(),
        sections: Sections {
            git: GitSection {
                packs: vec![pack_key],
                refs: [
                    ("refs/heads/main".to_owned(), head_sha),
                    (WORKTREE_TREE_REF.to_owned(), head_tree.clone()),
                    (INDEX_TREE_REF.to_owned(), head_tree),
                ]
                .into_iter()
                .collect(),
                head: "refs/heads/main".into(),
                fsck: FsckStatus::Verified,
            },
            workspace: WorkspaceSection {
                root: root_key,
                packs: vec![],
            },
            bulk: BulkState::pending(),
        },
        checkpoint: None,
    }
    .encode();
    let manifest_key = keys.manifest(&manifest.capture_id);
    sink.put_if_absent(&manifest_key, BlobSource::Bytes(&manifest.bytes))
        .unwrap();
    registrar
        .capture_register(&RegisterRequest {
            worktree_id: "wt".into(),
            epoch: 1,
            n: 0,
            parent: None,
            capture_id: manifest.capture_id.clone(),
            manifest_key,
            manifest: manifest.manifest.clone(),
        })
        .unwrap();
    manifest
}

/// Boot an executor on the chain head: materialize, open the engine seeded with the head.
fn boot(ws: &Path, sink: &LocalDir, head: &EncodedManifest) -> CaptureEngine {
    Materializer::new(sink, MaterializeTargets::new(ws, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    let mut engine =
        CaptureEngine::open(CaptureConfig::new("wt", 1, ws), Some(head.clone())).unwrap();
    engine.seed_tips_from_repo().unwrap();
    engine
}

/// Every tree the manifest's refs name is readable, the repository verifies, and the objects
/// reachable from the refs are the same set as in `truth`.
fn assert_complete(restored: &Path, truth: &Path, manifest: &Manifest) {
    let repo = GitRepo::open(restored).unwrap();
    assert_eq!(
        repo.fsck().unwrap(),
        FsckStatus::Verified,
        "fsck of {restored:?}"
    );
    for (name, sha) in &manifest.sections.git.refs {
        assert!(
            git_ok(restored, &["cat-file", "-t", sha]),
            "{name} → {sha} is in no pack the manifest lists"
        );
    }
    let tips = manifest.git_tips();
    assert_eq!(
        objects_from(restored, &tips),
        objects_from(truth, &tips),
        "the packs carry the closure of every tip"
    );
}

fn snap_ship(
    engine: &mut CaptureEngine,
    sink: &Arc<LocalDir>,
    registrar: &Arc<InMemoryRegistrar>,
    seq: u64,
) {
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Turn,
            class: Class::Small,
            seq,
        })
        .unwrap();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    assert_eq!(
        engine
            .shipper(sink.clone(), dyn_registrar)
            .ship_pending()
            .unwrap(),
        1
    );
}

/// The cluster session end to end: capture 0 from the control plane, an executor edits and
/// snaps, a replacement executor materializes the new head.
#[test]
fn tracked_files_matching_gitignore_survive_a_control_plane_base_and_the_next_capture_is_complete()
{
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let src = source(base);
    let sink = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let head0 = control_plane_base(base, &src, &sink, &registrar);

    // Executor 1 boots on capture 0.
    let ws = base.join("ws");
    let mut engine = boot(&ws, &sink, &head0);
    assert!(
        ws.join(".git/index").exists(),
        "the empty workspace class does not sweep the index the git class wrote"
    );
    assert_eq!(
        fs::read_to_string(ws.join("tooling/core.json")).unwrap(),
        "{\"strict\":true}\n"
    );
    assert_eq!(status(&ws), "", "a clean checkout of capture 0");
    assert!(git(&ws, &["ls-files"]).contains("tooling/core.json"));

    // An edit, a capture.
    fs::write(ws.join("GARAGE-PROOF.md"), "proof\n").unwrap();
    snap_ship(&mut engine, &sink, &registrar, 1);
    let head1 = registrar.head().unwrap();
    assert_eq!(head1.n, 1);
    let wt_tree = &head1.manifest.sections.git.refs[WORKTREE_TREE_REF];
    let listed = git(&ws, &["ls-tree", "-r", "--name-only", wt_tree]);
    assert!(
        listed.contains("tooling/core.json"),
        "tracked wins over `core.*`: {listed}"
    );
    assert!(listed.contains("GARAGE-PROOF.md"), "{listed}");
    assert_eq!(
        head1.manifest.sections.git.refs[INDEX_TREE_REF],
        head0.manifest.sections.git.refs[INDEX_TREE_REF],
        "nothing staged: the index tree is still the commit tree"
    );
    assert_eq!(
        head1.manifest.sections.git.packs.len(),
        2,
        "the project pack and this capture's: {:?}",
        head1.manifest.sections.git.packs
    );

    // Executor 2 (a resume after the pod was killed) materializes the head from the store.
    let ws2 = base.join("ws2");
    let restored_targets = MaterializeTargets::new(&ws2, None);
    let report = Materializer::new(sink.as_ref(), restored_targets)
        .materialize(&head1.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(report.fsck, Some(FsckStatus::Verified));
    assert_complete(&ws2, &ws, &head1.manifest);
    assert_eq!(
        fs::read_to_string(ws2.join("GARAGE-PROOF.md")).unwrap(),
        "proof\n"
    );
    assert_eq!(
        fs::read_to_string(ws2.join("tooling/core.json")).unwrap(),
        "{\"strict\":true}\n"
    );
    assert_eq!(status(&ws2), status(&ws));

    // And a runner reads the change: base commit against the worktree tree.
    let numstat = git(&ws2, &["diff", "--numstat", "HEAD", wt_tree]);
    assert_eq!(numstat, "1\t0\tGARAGE-PROOF.md", "only the edit differs");
}

/// The seed after a materialize records what the chain holds, not what the disk holds: a file
/// written between materialize and the engine's pickup (the harness is already running at
/// `capture.replan`) still ships with the next pack.
#[test]
fn a_file_written_before_the_seed_is_packed_by_the_next_capture() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let src = source(base);
    let sink = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let head0 = control_plane_base(base, &src, &sink, &registrar);

    let ws = base.join("ws");
    Materializer::new(sink.as_ref(), MaterializeTargets::new(&ws, None))
        .materialize(&head0.manifest, MaterializeClass::All)
        .unwrap();
    // Drift before the engine opens: a new file, a staged edit.
    fs::create_dir_all(ws.join("drift")).unwrap();
    fs::write(ws.join("drift/early.txt"), "written before pickup\n").unwrap();
    fs::write(ws.join("a.txt"), "one\nstaged\n").unwrap();
    git(&ws, &["add", "a.txt"]);
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &ws), Some(head0)).unwrap();
    engine.seed_tips_from_repo().unwrap();

    snap_ship(&mut engine, &sink, &registrar, 1);
    let head1 = registrar.head().unwrap();
    assert_ne!(
        head1.manifest.sections.git.refs[INDEX_TREE_REF],
        head1.manifest.sections.git.refs[WORKTREE_TREE_REF]
    );
    let ws2: PathBuf = base.join("ws2");
    let report = Materializer::new(sink.as_ref(), MaterializeTargets::new(&ws2, None))
        .materialize(&head1.manifest, MaterializeClass::Git)
        .unwrap();
    assert_eq!(report.fsck, Some(FsckStatus::Verified));
    assert_complete(&ws2, &ws, &head1.manifest);
    assert_eq!(
        fs::read_to_string(ws2.join("drift/early.txt")).unwrap(),
        "written before pickup\n"
    );
    assert_eq!(
        git(&ws2, &["diff", "--cached", "--stat"]),
        git(&ws, &["diff", "--cached", "--stat"])
    );
}
