//! Ownership on restore (Mend's ADR 0016, step 4): a capture made by root (files 0644,
//! directories 0755, transcripts 0600) restored under an owner map gives each person's saved
//! directory to their uid, makes the worktree, its git directory and the shared conversations
//! writable by the group, keeps a person's own files theirs, and `chown`s nothing but the person
//! directories and two roots. Captures record no owner.
//!
//! These need root (`chown`, a process as another uid). As anyone else they pass without
//! running, unless `SEALANTD_REQUIRE_ROOT_TESTS=1` (CI runs this file as root with it set).

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use sealant_capture::owners::OwnerMap;
use sealant_capture::{
    CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeReport, MaterializeTargets, Materializer, SnapRequest,
};

const GID: u32 = 40000;
const ALICE: u32 = 40012;
const BOB: u32 = 40031;

/// Whether the test can run: root, or a refusal when root tests are required.
fn root() -> bool {
    if nix::unistd::geteuid().is_root() {
        return true;
    }
    assert!(
        std::env::var("SEALANTD_REQUIRE_ROOT_TESTS").as_deref() != Ok("1"),
        "SEALANTD_REQUIRE_ROOT_TESTS=1 but not running as root"
    );
    eprintln!("not root: ownership tests skipped");
    false
}

fn owners() -> OwnerMap {
    OwnerMap {
        gid: GID,
        worktree: ALICE,
        people: [
            ("acct_alice".to_owned(), ALICE),
            ("acct_bob".to_owned(), BOB),
        ]
        .into(),
    }
}

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn write(path: &Path, bytes: &str, mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// `sh -c script` as `uid` with the shared group as its group: whether it succeeded.
fn as_user(uid: u32, script: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(script)
        .uid(uid)
        .gid(GID)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .status()
        .unwrap()
        .success()
}

fn stat(path: &Path) -> (u32, u32, u32) {
    let m = fs::symlink_metadata(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    (m.uid(), m.gid(), m.mode() & 0o7777)
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    home: PathBuf,
}

/// A worktree and harness home as root makes them under umask 022: tracked files 0644 and a
/// 0755 script, an untracked file, a `node_modules`, and three people's saved directories with
/// 0600 transcripts and Codex databases, one shared conversation each.
fn fixture(packages: usize) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_path_buf();
    // Every other uid passes through the test's directories.
    chmod(&base, 0o755);
    let root = base.join("ws");
    let home = base.join("home");
    fs::create_dir_all(&root).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    write(&root.join(".gitignore"), "node_modules/\n", 0o644);
    write(&root.join("a.txt"), "one\n", 0o644);
    write(&root.join("src/deep/lib.rs"), "fn f() {}\n", 0o644);
    write(&root.join("run.sh"), "#!/bin/sh\n", 0o755);
    write(&root.join("ro.txt"), "read only\n", 0o444);
    write(&root.join("tracked-600.txt"), "owner only\n", 0o600);
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);
    write(&root.join("notes.md"), "untracked\n", 0o644);
    write(&root.join("ro-untracked.txt"), "read only\n", 0o444);
    write(&root.join("private/key.txt"), "owner only\n", 0o600);
    chmod(&root.join("private"), 0o700);
    for p in 0..packages {
        write(
            &root.join(format!("node_modules/pkg{}/lib/m{p}.js", p % 100)),
            "module.exports = 1;\n",
            0o644,
        );
    }
    for person in ["acct_alice", "acct_bob", "acct_gone"] {
        let p = home.join("people").join(person);
        write(
            &p.join(".claude/projects/-workspace-repo/s.jsonl"),
            person,
            0o600,
        );
        write(&p.join("codex-db/state_5.sqlite"), person, 0o600);
        write(&p.join(".pi/agent/settings.json"), person, 0o644);
        let c = p.join("conversations/s1");
        write(&c.join("projects/-workspace-repo/t.jsonl"), person, 0o600);
        chmod(&c.join("projects/-workspace-repo"), 0o700);
        chmod(&c.join("projects"), 0o700);
        chmod(&c, 0o700);
        chmod(&p.join("conversations"), 0o2710);
        chmod(&p, 0o710);
    }
    write(&home.join(".codex/config.toml"), "model = \"x\"\n", 0o644);
    Fixture {
        _tmp: tmp,
        base,
        root,
        home,
    }
}

impl Fixture {
    fn config(&self, root: &Path, home: &Path) -> CaptureConfig {
        let mut c = CaptureConfig::new("wt-owners", 1, root);
        c.harness_home = Some(home.to_path_buf());
        c.racy_window = std::time::Duration::ZERO;
        c
    }

    /// Capture both classes, ship, and materialize into a fresh root and home under `owners`.
    fn restore(&self, owners: Option<OwnerMap>) -> (PathBuf, PathBuf, MaterializeReport) {
        let store = self.base.join("store");
        let sink = Arc::new(LocalDir::new(&store).unwrap());
        let registrar = Arc::new(InMemoryRegistrar::new("wt-owners", 1, None));
        let mut engine = CaptureEngine::open(self.config(&self.root, &self.home), None).unwrap();
        for (seq, class) in [(1, Class::Small), (2, Class::Bulk)] {
            engine
                .snap(SnapRequest {
                    kind: CaptureKind::Auto,
                    class,
                    seq,
                })
                .unwrap();
        }
        engine
            .shipper(sink.clone(), registrar.clone())
            .ship_pending()
            .unwrap();
        let restore = self.base.join("restore/repo");
        let home = self.base.join("restore/harness-home");
        fs::create_dir_all(restore.parent().unwrap()).unwrap();
        chmod(restore.parent().unwrap(), 0o755);
        // Executor preparation, as boot makes it: the worktree root the group's, with the
        // group's default ACL (what git itself creates in the git directory takes it).
        if let Some(owners) = &owners {
            owners.prepare_worktree_root(&restore).unwrap();
            sealant_capture::owners::apply_default_acl(&[&restore], owners.gid).unwrap();
        }
        let mut targets = MaterializeTargets::new(&restore, Some(home.clone()));
        targets.owners = owners;
        let report = Materializer::new(sink.as_ref(), targets)
            .materialize(&registrar.head().unwrap().manifest, MaterializeClass::All)
            .unwrap();
        (restore, home, report)
    }
}

/// A capture recorded 0644/0755 by root comes back writable, and creatable-in, by a second uid:
/// tracked files at two depths, an untracked file, `node_modules`, the git directory. The
/// worktree and git roots are the change's owner's, every entry takes the group, and only the
/// owner's bits are copied to the group (a 0444 pack stays 0444).
#[test]
fn a_root_made_capture_comes_back_writable_by_every_person() {
    if !root() {
        return;
    }
    let fx = fixture(50);
    let (repo, _, _) = fx.restore(Some(owners()));
    let r = repo.display();
    for script in [
        format!("echo x >> {r}/a.txt"),
        format!("echo x >> {r}/src/deep/lib.rs"),
        format!("echo x >> {r}/notes.md"),
        format!("echo x >> {r}/node_modules/pkg1/lib/m1.js"),
        format!("touch {r}/src/deep/new.rs && mkdir {r}/src/deep/newdir"),
        format!("touch {r}/node_modules/pkg1/lib/new.js"),
        format!("rm {r}/src/deep/lib.rs && echo again > {r}/src/deep/lib.rs"),
        format!("touch {r}/new-at-root && mkdir {r}/.git/refs/heads/bob"),
        format!("cat {r}/tracked-600.txt {r}/private/key.txt >/dev/null && ls {r}/private"),
        format!("echo x >> {r}/private/key.txt && touch {r}/private/new"),
    ] {
        assert!(as_user(BOB, &script), "as bob: {script}");
    }
    assert_eq!(stat(&repo), (ALICE, GID, 0o2775));
    assert_eq!(stat(&repo.join(".git")), (ALICE, GID, 0o2775));
    let (_, gid, mode) = stat(&repo.join("src/deep/lib.rs"));
    assert_eq!((gid, mode), (GID, 0o664));
    assert_eq!(stat(&repo.join("run.sh")).2, 0o775);
    assert_eq!(stat(&repo.join("src/deep")).2, 0o2775);
    assert_eq!(stat(&repo.join("notes.md")).2, 0o664);
    assert_eq!(stat(&repo.join("node_modules/pkg1/lib/m1.js")).2, 0o664);
    assert_eq!(stat(&repo.join("node_modules/pkg1")).2, 0o2775);
    assert_eq!(stat(&repo.join("ro.txt")).2, 0o444);
    assert_eq!(stat(&repo.join("ro-untracked.txt")).2, 0o444);
    // The owner's read goes to the group with the write: 0600 comes back 0660, never 0620.
    assert_eq!(stat(&repo.join("tracked-600.txt")).2, 0o660);
    assert_eq!(stat(&repo.join("private/key.txt")).2, 0o660);
    assert_eq!(stat(&repo.join("private")).2, 0o2770);
    // Made by bob in a setgid directory: the group's.
    assert_eq!(stat(&repo.join("src/deep/new.rs")).1, GID);
}

/// Each person's saved directory is theirs: the directory 0710, their transcripts, settings and
/// Codex databases at the recorded modes (0600 stays 0600). A 0600 transcript in a shared
/// conversation comes back group-writable, so the other person can append to it, and cannot read
/// the owner's own transcript. A removed member's directory, absent from the map, stays root's.
#[test]
fn each_person_s_saved_directory_is_restored_with_their_uid() {
    if !root() {
        return;
    }
    let fx = fixture(5);
    let (_, home, _) = fx.restore(Some(owners()));
    for (person, uid) in [("acct_alice", ALICE), ("acct_bob", BOB)] {
        let p = home.join("people").join(person);
        assert_eq!(stat(&p), (uid, GID, 0o710), "{person}");
        assert_eq!(
            stat(&p.join(".claude/projects/-workspace-repo/s.jsonl")),
            (uid, GID, 0o600)
        );
        assert_eq!(stat(&p.join(".claude/projects")).0, uid);
        assert_eq!(stat(&p.join("codex-db/state_5.sqlite")), (uid, GID, 0o600));
        assert_eq!(stat(&p.join(".pi/agent/settings.json")), (uid, GID, 0o644));
        assert_eq!(stat(&p.join("conversations")), (uid, GID, 0o2710));
        assert_eq!(stat(&p.join("conversations/s1")), (uid, GID, 0o2770));
        assert_eq!(
            stat(&p.join("conversations/s1/projects/-workspace-repo/t.jsonl")),
            (uid, GID, 0o660)
        );
    }
    let gone = home.join("people/acct_gone");
    assert_eq!(stat(&gone).0, 0);
    assert_eq!(
        stat(&gone.join(".claude/projects/-workspace-repo/s.jsonl")),
        (0, 0, 0o600)
    );
    assert_eq!(stat(&home).0, 0);
    assert_eq!(stat(&home.join(".codex/config.toml")).0, 0);

    let alice = home.join("people/acct_alice");
    let shared = alice.join("conversations/s1/projects/-workspace-repo/t.jsonl");
    let own = alice.join(".claude/projects/-workspace-repo/s.jsonl");
    assert!(as_user(BOB, &format!("echo turn >> {}", shared.display())));
    assert!(as_user(
        BOB,
        &format!(
            "touch {}",
            alice.join("conversations/s1/projects/new.jsonl").display()
        )
    ));
    assert!(!as_user(BOB, &format!("cat {} >/dev/null", own.display())));
    assert!(!as_user(BOB, &format!("ls {} >/dev/null", alice.display())));
    assert!(as_user(ALICE, &format!("echo x >> {}", own.display())));
}

/// Nothing outside the person directories is `chown`ed: the count is one per entry of the two
/// mapped people's directories plus the worktree and git roots, whatever the size of the
/// worktree (the syscall budget of ADR 0016: the restore's `chmod`s are the ones it made before,
/// with bits added). Without a map nothing is `chown`ed at all.
#[test]
fn only_the_person_directories_are_chowned() {
    if !root() {
        return;
    }
    let people_entries = |home: &Path| -> u64 {
        ["acct_alice", "acct_bob"]
            .iter()
            .map(|p| {
                walkdir::WalkDir::new(home.join("people").join(p))
                    .into_iter()
                    .count() as u64
            })
            .sum()
    };
    for packages in [10, 2000] {
        let fx = fixture(packages);
        let (_, home, report) = fx.restore(Some(owners()));
        assert_eq!(
            report.owned,
            people_entries(&home) + 2,
            "{packages} packages"
        );
        let fx = fixture(packages);
        let (_, _, plain) = fx.restore(None);
        assert_eq!(plain.owned, 0);
        assert_eq!(plain.files, report.files);
    }
}

/// Captures record no owner: the restored tree, captured again, gives the same workspace tree
/// once every person's entries are handed to other uids.
#[test]
fn captures_record_no_owner() {
    if !root() {
        return;
    }
    let fx = fixture(5);
    let (repo, home, _) = fx.restore(Some(owners()));
    let workspace_root = |seq: u64| {
        let mut engine = CaptureEngine::open(fx.config(&repo, &home), None).unwrap();
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Checkpoint,
                class: Class::Small,
                seq,
            })
            .unwrap()
            .manifest
            .manifest
            .sections
            .workspace
            .root
            .clone()
    };
    let before = workspace_root(1);
    for entry in walkdir::WalkDir::new(home.join("people")) {
        let entry = entry.unwrap();
        std::os::unix::fs::lchown(entry.path(), Some(50_000), Some(50_000)).unwrap();
    }
    assert_eq!(workspace_root(2), before);
}

/// Executor preparation: the group's default ACL on the worktree root, so a file a root process
/// creates there under umask 022 is still the group's to write.
#[test]
fn the_default_acl_makes_new_files_group_writable() {
    if !root() {
        return;
    }
    if Command::new("setfacl").arg("--version").output().is_err() {
        assert!(
            std::env::var("SEALANTD_REQUIRE_ROOT_TESTS").as_deref() != Ok("1"),
            "setfacl is required"
        );
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    chmod(tmp.path(), 0o755);
    let root = tmp.path().join("repo");
    owners().prepare_worktree_root(&root).unwrap();
    sealant_capture::owners::apply_default_acl(&[&root, &tmp.path().join("absent")], GID).unwrap();
    assert_eq!(stat(&root), (ALICE, GID, 0o2775));
    let made = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "umask 022 && mkdir {0}/d && echo x > {0}/d/f",
            root.display()
        ))
        .status()
        .unwrap();
    assert!(made.success());
    assert_eq!(stat(&root.join("d")).1, GID);
    assert!(as_user(BOB, &format!("echo y >> {}/d/f", root.display())));
    assert!(as_user(BOB, &format!("touch {}/d/g", root.display())));
}

/// In a restored worktree (its files root's, the group's to write), a second person changes the
/// lockfile and runs `pnpm install` and `npm install`, then `pnpm install --force` and
/// `npm rebuild`, started through sealantd's own identity switch
/// (`sealant_process::identity::RunAs::apply`). pnpm relinks bins with a `chmod`, so it needs
/// `CAP_FOWNER`: it passes where the person gets it, and fails with `ERR_PNPM_CMD_SHIM_CHMOD`
/// where no-new-privileges withholds it (npm ignores the error). Needs root, network, pnpm and
/// npm; it makes a group and a user for the person.
#[test]
fn install_after_a_lockfile_change_as_a_person() {
    if !root() {
        return;
    }
    person_user();
    let fowner = sealant_process::identity::fowner_withheld().is_none();
    let mut failed = Vec::new();
    for pm in ["pnpm", "npm"] {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();
        chmod(&base, 0o755);
        // A store and caches the group shares, as the images keep them under /var/cache.
        let shared = base.join("cache");
        fs::create_dir_all(&shared).unwrap();
        std::os::unix::fs::chown(&shared, None, Some(GID)).unwrap();
        chmod(&shared, 0o2775);
        sealant_capture::owners::apply_default_acl(&[&shared], GID).unwrap();
        let bob_home = base.join("bob");
        fs::create_dir_all(&bob_home).unwrap();
        std::os::unix::fs::chown(&bob_home, Some(BOB), Some(GID)).unwrap();
        let env = format!(
            "HOME={home} npm_config_store_dir={c}/pnpm-store npm_config_cache={c}/npm \
             XDG_CACHE_HOME={c}/xdg CI=1",
            home = bob_home.display(),
            c = shared.display()
        );

        let root = base.join("ws");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        write(&root.join(".gitignore"), "node_modules/\n", 0o644);
        write(
            &root.join("package.json"),
            r#"{"name":"x","version":"1.0.0","dependencies":{"semver":"7.6.0"}}"#,
            0o644,
        );
        // Installed by root under umask 022, as every capture before the per-person layout.
        let install = |as_bob: bool, root: &Path| -> (bool, String) {
            let flags = if pm == "pnpm" {
                format!(
                    "--no-frozen-lockfile --store-dir {}/pnpm-store",
                    shared.display()
                )
            } else {
                String::new()
            };
            let script = format!(
                "cd {} && env {env} {pm} install {flags} 2>&1; echo \"exit=$?\"",
                root.display()
            );
            let out = if as_bob {
                bob_command(&format!("umask 0002; {script}"))
                    .env_clear()
                    .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                    .output()
                    .unwrap()
            } else {
                Command::new("sh")
                    .arg("-c")
                    .arg(format!("umask 022; {script}"))
                    .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                    .output()
                    .unwrap()
            };
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            (text.trim_end().ends_with("exit=0"), text)
        };
        let (ok, text) = install(false, &root);
        assert!(ok, "{pm} as root: {text}");
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "deps"]);
        let fx = Fixture {
            _tmp: tempfile::tempdir().unwrap(),
            base: base.clone(),
            root: root.clone(),
            home: base.join("home"),
        };
        fs::create_dir_all(&fx.home).unwrap();
        let (repo, _, _) = fx.restore(Some(owners()));
        // A lockfile change that keeps the restored package with a bin (its bin is relinked and
        // its target `chmod`ed, a root-owned file) and adds another.
        write(
            &repo.join("package.json"),
            r#"{"name":"x","version":"1.0.0","dependencies":{"semver":"7.6.0","which":"4.0.0"}}"#,
            0o664,
        );
        std::os::unix::fs::chown(repo.join("package.json"), Some(BOB), Some(GID)).unwrap();
        let (ok, text) = install(true, &repo);
        eprintln!("== {pm} install as a person after a restore: ok={ok}\n{text}");
        // And a forced reinstall over every restored package.
        let forced = bob_command(&format!(
            "umask 0002; cd {} && env {env} {pm} {} 2>&1; echo \"exit=$?\"",
            repo.display(),
            if pm == "pnpm" {
                format!(
                    "install --force --store-dir {}/pnpm-store",
                    shared.display()
                )
            } else {
                "rebuild".to_owned()
            }
        ))
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .output()
        .unwrap();
        let forced = String::from_utf8_lossy(&forced.stdout).into_owned();
        eprintln!("== {pm} forced, as a person:\n{forced}");
        let bin = repo.join("node_modules/.bin/semver");
        eprintln!(
            "{pm}: node_modules/.bin/semver runs: {}",
            Command::new(&bin)
                .arg("--help")
                .output()
                .is_ok_and(|o| o.status.success())
        );
        let passed = ok && forced.trim_end().ends_with("exit=0");
        if pm == "pnpm" && !fowner {
            // pnpm 12 says ERR_PNPM_CMD_SHIM_CHMOD; pnpm 9 a bare EPERM on the chmod.
            assert!(
                text.contains("ERR_PNPM_CMD_SHIM_CHMOD")
                    || text.contains("EPERM: operation not permitted, chmod"),
                "{text}"
            );
        } else if !passed {
            failed.push(pm);
        }
    }
    assert!(failed.is_empty(), "failed as a person: {failed:?}");
}

/// A passwd entry for [`BOB`] (uid 40031, primary group [`GID`]), so sealantd's identity switch
/// can resolve it. Made once; one already there is kept.
fn person_user() {
    static MADE: std::sync::Once = std::sync::Once::new();
    MADE.call_once(|| {
        let has = |db: &str, key: u32| {
            Command::new("getent")
                .args([db, &key.to_string()])
                .output()
                .is_ok_and(|o| o.status.success())
        };
        if !has("group", GID) {
            assert!(
                Command::new("groupadd")
                    .args(["-g", &GID.to_string(), "mtestmend"])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        if !has("passwd", BOB) {
            assert!(
                Command::new("useradd")
                    .args([
                        "-m",
                        "-u",
                        &BOB.to_string(),
                        "-g",
                        &GID.to_string(),
                        "mtestperson"
                    ])
                    .status()
                    .unwrap()
                    .success()
            );
        }
    });
}

/// `sh -c script` as Bob, started as sealantd starts a person's process.
fn bob_command(script: &str) -> Command {
    let mut c = Command::new("sh");
    c.arg("-c").arg(script);
    // Bob is in Mend's reserved range and group, as a person without an owner map is.
    sealant_process::identity::RunAs::resolve(
        &BOB.to_string(),
        &sealant_process::identity::People::Reserved,
    )
    .unwrap()
    .apply(&mut c);
    c
}
