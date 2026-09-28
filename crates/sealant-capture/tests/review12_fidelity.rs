//! What a sealed final flush holds is what the disk held, and it comes back as the disk held it
//! (review 2026-09-28, twelfth pass):
//!
//! - opening the capture keeps the user's `.git/info/exclude` byte for byte, a legacy-encoded
//!   one included: the daemon's rule is appended to the bytes, never to a decoded copy (#1);
//! - a cold restore gives back every hardlink group across classes as one inode: pnpm's
//!   peer-context copies of a local package (two bulk names of a tracked file's inode), a
//!   tracked file with a workspace name and two bulk names, a workspace file with two bulk
//!   names (#2);
//! - a final flush over an unchanged disk asks the registrar where a refused seal stands again,
//!   once per final flush, so a registrar that has recovered is heard (#4).

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sealant_capture::registrar::{
    ChangeSummaryRequest, HeartbeatRequest, HeartbeatResponse, PlanGetRequest, PlanGetResponse,
    RegisterRequest, RegisterResponse, RegistrarError, SealAnswer, SealState,
    UploadCompleteRequest, UploadCompleteResponse, UploadUrlsRequest, UploadUrlsResponse,
};
use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, MaterializeClass,
    MaterializeTargets, Materializer, Registrar,
};

const EXECUTOR: &str = "exec-r12";

fn git_out(root: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git")
}

fn git(root: &Path, args: &[&str]) -> String {
    let out = git_out(root, args);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

struct Fixture {
    tmp: tempfile::TempDir,
    root: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    /// A repository with one commit on `main`: `a` holding `base\n`; `.gitignore` ignoring
    /// `ignored/` (the workspace class) and `node_modules/` (the bulk class).
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("a"), b"base\n").unwrap();
        fs::write(root.join(".gitignore"), b"ignored/\nnode_modules/\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "base"]);
        Self {
            store: Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap()),
            registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None).with_executor(EXECUTOR)),
            root,
            tmp,
        }
    }

    fn config(&self) -> CaptureConfig {
        let mut config = CaptureConfig::new("wt", 1, &self.root);
        config.executor = Some(EXECUTOR.to_owned());
        config
    }

    fn runner(&self, registrar: Arc<dyn Registrar>) -> CadenceRunner {
        let engine = CaptureEngine::open(self.config(), None).unwrap();
        let shipper = Arc::new(engine.shipper(self.store.clone(), registrar));
        CadenceRunner::new(engine, shipper)
    }

    /// A final flush that must say `complete` and seal the chain.
    fn final_flush(&self) {
        let result = self.runner(self.registrar.clone()).flush_final(None);
        assert!(result.complete(), "{result:?}");
        assert!(!self.registrar.seals().is_empty(), "the seal is recorded");
    }

    /// A full cold restore of the sealed head into a fresh directory.
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

/// Every file under `root` (`.git` and `.sealantd` left out), grouped by inode: the groups of
/// two or more names, sorted.
fn inode_groups(root: &Path) -> Vec<Vec<PathBuf>> {
    fn visit(root: &Path, rel: &Path, out: &mut BTreeMap<(u64, u64), Vec<PathBuf>>) {
        for entry in fs::read_dir(root.join(rel)).unwrap() {
            let entry = entry.unwrap();
            if rel.as_os_str().is_empty()
                && [".git", ".sealantd"].contains(&entry.file_name().to_str().unwrap_or_default())
            {
                continue;
            }
            let path = rel.join(entry.file_name());
            let meta = fs::symlink_metadata(root.join(&path)).unwrap();
            if meta.is_dir() {
                visit(root, &path, out);
            } else if meta.is_file() {
                out.entry((meta.dev(), meta.ino())).or_default().push(path);
            }
        }
    }
    let mut map = BTreeMap::new();
    visit(root, Path::new(""), &mut map);
    let mut groups: Vec<Vec<PathBuf>> = map
        .into_values()
        .filter(|g| g.len() > 1)
        .map(|mut g| {
            g.sort();
            g
        })
        .collect();
    groups.sort();
    groups
}

/// Link `names` (worktree-relative) to `first`, creating their directories.
fn link_all(root: &Path, first: &str, names: &[&str]) {
    for name in names {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::hard_link(root.join(first), path).unwrap();
    }
}

/// Restore the sealed head and check that every name of `names` is one inode, as on the
/// source, and that the whole inode groups match; then write through `names[0]` and read the
/// new bytes through every other name.
fn assert_one_inode_after_restore(fx: &Fixture, name: &str, names: &[&str]) {
    let before = inode_groups(&fx.root);
    let out = fx.restore(name);
    let after = inode_groups(&out);
    assert_eq!(after, before, "every hardlink group comes back whole");
    let inodes: Vec<u64> = names
        .iter()
        .map(|n| fs::metadata(out.join(n)).unwrap().ino())
        .collect();
    assert!(
        inodes.iter().all(|i| *i == inodes[0]),
        "one inode for {names:?}: {inodes:?}"
    );
    fs::write(out.join(names[0]), b"a later edit through one name\n").unwrap();
    for n in &names[1..] {
        assert_eq!(
            fs::read(out.join(n)).unwrap(),
            b"a later edit through one name\n",
            "{n} sees the edit"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// #1: a legacy-encoded `.git/info/exclude`.
// ---------------------------------------------------------------------------------------------

/// A valid exclude file with a Latin-1 byte in a comment: git reads it, and so must the
/// capture. Opening the engine appends its rule to the user's bytes; the sealed restore holds
/// them too.
#[test]
fn a_raw_byte_git_exclude_survives_capture_open_and_restore() {
    let fx = Fixture::new();
    let owned = b"# user exclusion caf\xe9\nuser-private.txt\n";
    let exclude = fx.root.join(".git/info/exclude");
    fs::write(&exclude, owned).unwrap();
    fs::write(fx.root.join("user-private.txt"), b"own local notes\n").unwrap();
    assert_eq!(
        git(&fx.root, &["check-ignore", "user-private.txt"]),
        "user-private.txt"
    );
    fx.final_flush();
    let after = fs::read(&exclude).unwrap();
    assert!(
        after.starts_with(owned),
        "the user's exclude bytes survive opening the capture: {after:?}"
    );
    assert!(after.ends_with(b"\n/.sealantd/\n"), "{after:?}");
    assert_eq!(
        git(&fx.root, &["check-ignore", "user-private.txt"]),
        "user-private.txt"
    );
    let out = fx.restore("raw-exclude");
    let restored = fs::read(out.join(".git/info/exclude")).unwrap();
    assert!(restored.starts_with(owned), "{restored:?}");
    // Opening it again appends nothing more.
    drop(CaptureEngine::open(fx.config(), None).unwrap());
    assert_eq!(fs::read(&exclude).unwrap(), after);
}

/// An exclude file that cannot be read (no read permission) is left as it is: only a missing
/// file reads as empty. Needs a user the permission binds (not root).
#[test]
fn an_unreadable_git_exclude_is_never_replaced() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new();
    let exclude = fx.root.join(".git/info/exclude");
    fs::write(&exclude, b"user-private.txt\n").unwrap();
    fs::set_permissions(&exclude, fs::Permissions::from_mode(0o200)).unwrap();
    if fs::read(&exclude).is_ok() {
        eprintln!("running as a user file permissions do not bind: passed over");
        return;
    }
    let repo = sealant_capture::gitpack::GitRepo::open(&fx.root).unwrap();
    assert!(repo.exclude_locally("/.sealantd/").is_err());
    fs::set_permissions(&exclude, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(fs::read(&exclude).unwrap(), b"user-private.txt\n");
    // Missing: created with the rule alone.
    fs::remove_file(&exclude).unwrap();
    repo.exclude_locally("/.sealantd/").unwrap();
    assert_eq!(fs::read(&exclude).unwrap(), b"/.sealantd/\n");
    // Its mode is kept when the rule is appended.
    fs::write(&exclude, b"own\n").unwrap();
    fs::set_permissions(&exclude, fs::Permissions::from_mode(0o600)).unwrap();
    repo.exclude_locally("/other/").unwrap();
    assert_eq!(fs::read(&exclude).unwrap(), b"own\n/other/\n");
    assert_eq!(fs::metadata(&exclude).unwrap().mode() & 0o7777, 0o600);
}

// ---------------------------------------------------------------------------------------------
// #2: hardlink groups across classes come back as one inode.
// ---------------------------------------------------------------------------------------------

/// pnpm's peer-context layout, by hand: a tracked local package's file, and two copies of it
/// under `node_modules/.pnpm` (one per peer context), all one inode. The capture names the
/// tracked file and one bulk name (`shared`), and the two bulk names as a bulk hardlink group.
#[test]
fn a_tracked_file_with_two_bulk_names_restores_as_one_inode() {
    let fx = Fixture::new();
    fs::create_dir_all(fx.root.join("packages/util")).unwrap();
    fs::write(
        fx.root.join("packages/util/index.js"),
        b"module.exports = require('peer');\n",
    )
    .unwrap();
    git(&fx.root, &["add", "-A"]);
    git(&fx.root, &["commit", "-qm", "util"]);
    let names = [
        "packages/util/index.js",
        "node_modules/.pnpm/util@file+packages+util_peer@1.0.0/node_modules/util/index.js",
        "node_modules/.pnpm/util@file+packages+util_peer@2.0.0/node_modules/util/index.js",
    ];
    link_all(&fx.root, names[0], &names[1..]);
    fx.final_flush();
    assert_one_inode_after_restore(&fx, "tracked-two-bulk", &names);
}

/// A tracked file with a name in the workspace class and two in the bulk class.
#[test]
fn a_tracked_file_with_workspace_and_two_bulk_names_restores_as_one_inode() {
    let fx = Fixture::new();
    fs::write(fx.root.join("shared.js"), b"module.exports = 42;\n").unwrap();
    git(&fx.root, &["add", "-A"]);
    git(&fx.root, &["commit", "-qm", "shared"]);
    let names = [
        "shared.js",
        "ignored/shared.js",
        "node_modules/pkg/a.js",
        "node_modules/pkg/b.js",
    ];
    link_all(&fx.root, names[0], &names[1..]);
    fx.final_flush();
    assert_one_inode_after_restore(&fx, "tracked-workspace-bulk", &names);
}

/// A file in the workspace class (no tracked name) with two names in the bulk class.
#[test]
fn a_workspace_file_with_two_bulk_names_restores_as_one_inode() {
    let fx = Fixture::new();
    fs::create_dir_all(fx.root.join("ignored")).unwrap();
    fs::write(
        fx.root.join("ignored/work.txt"),
        b"own work shared with dependencies\n",
    )
    .unwrap();
    let names = [
        "ignored/work.txt",
        "node_modules/pkg/a",
        "node_modules/pkg/b",
    ];
    link_all(&fx.root, names[0], &names[1..]);
    fx.final_flush();
    assert_one_inode_after_restore(&fx, "workspace-two-bulk", &names);
}

/// Once every link is made, a strict apply checks the whole topology: names a class restored
/// as one group that are on two inodes of one filesystem fail it, a lenient one says so and
/// goes on.
#[test]
fn a_split_restored_group_fails_a_strict_apply() {
    use sealant_capture::worktree_meta::{
        self, LinkClass, MetaError, MetaScope, RestoredGroups, RestoredName,
    };
    let fx = Fixture::new();
    fs::create_dir_all(fx.root.join("node_modules/pkg")).unwrap();
    fs::write(fx.root.join("node_modules/pkg/a"), b"same\n").unwrap();
    fs::write(fx.root.join("node_modules/pkg/b"), b"same\n").unwrap();
    let tree = git(&fx.root, &["write-tree"]);
    let repo = sealant_capture::gitpack::GitRepo::open(&fx.root).unwrap();
    let scope = MetaScope {
        root: fx.root.clone(),
        excludes: vec![".sealantd".to_owned()],
        bulk_dirs: vec!["node_modules".to_owned()],
        nested: Vec::new(),
        skip_abs: Vec::new(),
    };
    let doc = worktree_meta::capture(&repo, &tree, &scope, None)
        .unwrap()
        .doc;
    let mut restored = RestoredGroups::default();
    restored.add(
        ["a", "b"]
            .iter()
            .map(|n| RestoredName {
                class: LinkClass::Bulk,
                key: None,
                abs: fx.root.join("node_modules/pkg").join(n),
            })
            .collect(),
    );
    let resolve = |_: LinkClass, _: &[u8]| -> Option<PathBuf> { None };
    let refused = worktree_meta::apply_over(&repo, &doc, &scope, &resolve, &restored, true);
    assert!(
        matches!(refused, Err(MetaError::LinkUnfulfilled { .. })),
        "{refused:?}"
    );
    worktree_meta::apply_over(&repo, &doc, &scope, &resolve, &restored, false).unwrap();
}

/// `node` and `pnpm` on `PATH`, for the real installation below.
fn pnpm_available() -> bool {
    ["node", "pnpm"].iter().all(|tool| {
        Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

fn run_at(root: &Path, home: &Path, program: &str, args: &[&str]) -> Output {
    let output = Command::new(program)
        .current_dir(root)
        .args(args)
        .env("HOME", home)
        .env("npm_config_update_notifier", "false")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// A real `pnpm install` (hardlink import) of two local consumers of a local package with a
/// peer dependency in two versions: pnpm makes two peer-context copies of the package's files,
/// both on the tracked source's inode, with no link made by hand. After a sealed final flush
/// and a cold restore, an edit to the tracked source reaches both consumers, as it does on the
/// source disk. Needs `node` and `pnpm` on `PATH`; passed over (saying so) without them — the
/// hand-made layout above is the same topology.
#[test]
fn a_real_pnpm_peer_context_install_restores_its_hardlinks() {
    if !pnpm_available() {
        eprintln!("node and pnpm are not on PATH: the real pnpm installation is passed over");
        return;
    }
    let fx = Fixture::new();
    let home = fx.tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    for pkg in ["util", "one", "two", "peer1", "peer2"] {
        fs::create_dir_all(fx.root.join("packages").join(pkg)).unwrap();
    }
    for (name, version) in [("peer1", "1.0.0"), ("peer2", "2.0.0")] {
        fs::write(
            fx.root.join(format!("packages/{name}/package.json")),
            format!(r#"{{"name":"peer","version":"{version}","main":"index.js"}}"#),
        )
        .unwrap();
        fs::write(
            fx.root.join(format!("packages/{name}/index.js")),
            format!("module.exports='{version}';\n"),
        )
        .unwrap();
    }
    fs::write(
        fx.root.join("packages/util/package.json"),
        br#"{"name":"local-util","version":"1.0.0","main":"index.js","peerDependencies":{"peer":"*"}}"#,
    )
    .unwrap();
    fs::write(
        fx.root.join("packages/util/index.js"),
        b"module.exports = require('peer');\n",
    )
    .unwrap();
    for (name, peer) in [("one", "peer1"), ("two", "peer2")] {
        fs::write(
            fx.root.join(format!("packages/{name}/package.json")),
            format!(
                r#"{{"name":"{name}","version":"1.0.0","main":"index.js","dependencies":{{"local-util":"file:../util","peer":"file:../{peer}"}}}}"#
            ),
        )
        .unwrap();
        fs::write(
            fx.root.join(format!("packages/{name}/index.js")),
            b"module.exports=require('local-util');\n",
        )
        .unwrap();
    }
    fs::write(
        fx.root.join("package.json"),
        br#"{"name":"peer-contexts","private":true,"version":"1.0.0","dependencies":{"one":"file:./packages/one","two":"file:./packages/two"}}"#,
    )
    .unwrap();
    git(&fx.root, &["add", "-A"]);
    git(&fx.root, &["commit", "-qm", "peer contexts"]);
    let store = fx.tmp.path().join("pnpm-store");
    run_at(
        &fx.root,
        &home,
        "pnpm",
        &[
            "install",
            "--store-dir",
            store.to_str().unwrap(),
            "--package-import-method=hardlink",
            "--ignore-scripts",
        ],
    );
    let read = "console.log(require('one'), require('two'))";
    let values = run_at(&fx.root, &home, "node", &["-e", read]);
    assert_eq!(values.stdout, b"1.0.0 2.0.0\n");
    let groups = inode_groups(&fx.root);
    assert!(
        groups.iter().any(|g| {
            g.iter().filter(|p| p.starts_with("node_modules")).count() > 1
                && g.iter().any(|p| p.starts_with("packages"))
        }),
        "pnpm made a tracked file with several bulk names: {groups:?}"
    );
    fx.final_flush();
    let out = fx.restore("pnpm-peer-contexts");
    assert_eq!(
        inode_groups(&out),
        groups,
        "every hardlink group comes back whole"
    );
    fs::write(
        out.join("packages/util/index.js"),
        b"module.exports='new user edit';\n",
    )
    .unwrap();
    let values = run_at(&out, &home, "node", &["-e", read]);
    assert_eq!(values.stdout, b"new user edit new user edit\n");
}

// ---------------------------------------------------------------------------------------------
// #4: a refused seal is asked about again by the next final flush.
// ---------------------------------------------------------------------------------------------

/// The in-memory registrar, answering the first `refuse` registers of a sealing capture
/// `refused (unrestorable)` (a registrar that could not read the objects), and counting them.
struct RefusingSeals {
    inner: Arc<InMemoryRegistrar>,
    refuse: usize,
    sealing: AtomicUsize,
}

impl RefusingSeals {
    fn new(inner: Arc<InMemoryRegistrar>, refuse: usize) -> Self {
        // The refused registers record nothing on the inner registrar either.
        inner.withhold_seals(refuse);
        Self {
            inner,
            refuse,
            sealing: AtomicUsize::new(0),
        }
    }
}

impl Registrar for RefusingSeals {
    fn plan_get(&self, r: &PlanGetRequest) -> Result<PlanGetResponse, RegistrarError> {
        self.inner.plan_get(r)
    }
    fn upload_urls(&self, r: &UploadUrlsRequest) -> Result<UploadUrlsResponse, RegistrarError> {
        self.inner.upload_urls(r)
    }
    fn upload_complete(
        &self,
        r: &UploadCompleteRequest,
    ) -> Result<UploadCompleteResponse, RegistrarError> {
        self.inner.upload_complete(r)
    }
    fn capture_register(&self, r: &RegisterRequest) -> Result<RegisterResponse, RegistrarError> {
        let mut answer = self.inner.capture_register(r)?;
        if r.manifest.final_seal.is_some()
            && self.sealing.fetch_add(1, Ordering::SeqCst) < self.refuse
        {
            answer.seal = Some(SealAnswer::not_standing(SealState::Refused, "unrestorable"));
        }
        Ok(answer)
    }
    fn lease_heartbeat(&self, r: &HeartbeatRequest) -> Result<HeartbeatResponse, RegistrarError> {
        self.inner.lease_heartbeat(r)
    }
    fn change_summary(&self, r: &ChangeSummaryRequest) -> Result<(), RegistrarError> {
        self.inner.change_summary(r)
    }
}

/// The registrar refuses the seal once (it could not read the objects) and then recovers: the
/// next final flush over the unchanged disk asks again and completes.
#[test]
fn a_refused_seal_is_asked_again_once_the_registrar_recovers() {
    let fx = Fixture::new();
    let registrar = Arc::new(RefusingSeals::new(fx.registrar.clone(), 1));
    let runner = fx.runner(registrar.clone());
    let first = runner.flush_final(None);
    assert!(!first.complete(), "{first:?}");
    assert_eq!(registrar.sealing.load(Ordering::SeqCst), 1);
    let head = fx.registrar.head().unwrap().capture_id;
    let again = runner.flush_final(None);
    assert!(
        again.complete(),
        "the recovered registrar is asked: {again:?}"
    );
    assert_eq!(
        registrar.sealing.load(Ordering::SeqCst),
        2,
        "one more sealing register"
    );
    assert_eq!(
        fx.registrar.head().unwrap().capture_id,
        head,
        "nothing new staged: the same sealing capture, asked again"
    );
    assert_eq!(fx.registrar.seals().len(), 1, "the seal is recorded");
    // Recorded: a final flush asked again does not ask again.
    assert!(runner.flush_final(None).complete());
    assert_eq!(registrar.sealing.load(Ordering::SeqCst), 2);
}

/// A registrar that keeps refusing: every final flush asks it once more, and no more than once.
#[test]
fn a_refused_seal_is_asked_once_per_final_flush() {
    let fx = Fixture::new();
    let registrar = Arc::new(RefusingSeals::new(fx.registrar.clone(), usize::MAX / 2));
    let runner = fx.runner(registrar.clone());
    for flush in 1..=4 {
        let result = runner.flush_final(None);
        assert!(!result.complete(), "{result:?}");
        assert!(format!("{result:?}").contains("unrestorable"), "{result:?}");
        assert_eq!(registrar.sealing.load(Ordering::SeqCst), flush);
    }
    assert!(fx.registrar.seals().is_empty());
}
