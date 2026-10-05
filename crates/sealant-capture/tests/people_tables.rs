//! Mend's per-person layout (its ADR 0016) keeps each person's saved directory under the harness
//! home at `people/<account id>/`, laid out as their home is. The credential and machine-state
//! tables apply under every one of them as at the root: no person's login is captured, or
//! restored into anyone's executor, from a saved directory either. Codex's databases live in
//! `people/<id>/codex-db/`: the thread index and memory database are saved with their WAL, the
//! logs database and every `-shm` file are not.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use sealant_capture::gitpack::GitRepo;
use sealant_capture::index::{self, CredentialKind};
use sealant_capture::manifest::WorkspaceSection;
use sealant_capture::roots::ClassRoots;
use sealant_capture::sink::{BlobSink, BlobSource};
use sealant_capture::tree::{DirEntry, DirObject};
use sealant_capture::{
    CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, SnapRequest,
};

const PEOPLE: [&str; 2] = ["acct_alice", "acct_bob"];

fn git(root: &Path, args: &[&str]) {
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
}

fn write(path: &Path, bytes: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// Every path a person's saved directory may hold that is never saved: each listed file with a
/// write's temporary and a lock beside it, each listed directory with a file inside, a name each
/// pattern matches, and Codex's logs database with its WAL and shared memory.
fn never_saved() -> Vec<String> {
    let mut paths = Vec::new();
    for c in index::harness_exclusions() {
        match c.kind {
            CredentialKind::File => {
                paths.push(c.path.to_owned());
                paths.push(format!("{}.mend-seed-12", c.path));
                paths.push(format!("{}.lock", c.path));
            }
            CredentialKind::Dir => paths.push(format!("{}/nested/token", c.path)),
            CredentialKind::Pattern => paths.push(c.path.replace('*', "9.sqlite")),
        }
    }
    for name in [
        "logs_2.sqlite",
        "logs_2.sqlite-wal",
        "logs_2.sqlite-shm",
        "state_5.sqlite-shm",
        "memories_1.sqlite-shm",
        "goals_1.sqlite-shm",
    ] {
        paths.push(format!("codex-db/{name}"));
    }
    paths
}

/// What a person's saved directory holds that is saved: conversations, settings beside the
/// logins, and Codex's thread index and memory database with their WALs.
const SAVED: &[&str] = &[
    ".claude/projects/-workspace-repo/s1.jsonl",
    ".claude/todos/t.json",
    ".codex/sessions/2026/10/06/rollout-1.jsonl",
    ".codex/config.toml",
    ".pi/agent/sessions/s.jsonl",
    ".pi/agent/settings.json",
    ".local/share/opencode/opencode.db",
    "codex-db/state_5.sqlite",
    "codex-db/state_5.sqlite-wal",
    "codex-db/memories_1.sqlite",
    "codex-db/memories_1.sqlite-wal",
    "conversations/s1/sessions/rollout-2.jsonl",
];

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn build() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();
        let root = base.join("ws");
        let home = base.join("home");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        write(&root.join("a.txt"), "one\n");
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        for person in PEOPLE {
            let p = home.join("people").join(person);
            for path in never_saved() {
                write(&p.join(path), "{\"token\":\"secret\"}");
            }
            for path in SAVED {
                write(&p.join(path), person);
            }
        }
        // The same at the root of the home, as today's layout holds it.
        write(&home.join(".codex/auth.json"), "{\"token\":\"secret\"}");
        write(&home.join(".codex/config.toml"), "model = \"x\"\n");
        Self {
            _tmp: tmp,
            base,
            root,
            home,
        }
    }

    fn config(&self) -> CaptureConfig {
        let mut c = CaptureConfig::new("wt-people", 1, &self.root);
        c.harness_home = Some(self.home.clone());
        c.racy_window = std::time::Duration::ZERO;
        c
    }
}

/// A person directory with every listed path in it (a regular `auth.json` included, where Mend
/// keeps a link to the home) is captured without any of them, and restores none of them: Codex's
/// `codex-db` comes back with its databases and their WALs, and without its logs database or any
/// `-shm` file.
#[test]
fn a_person_s_saved_directory_is_captured_and_restored_without_a_login() {
    let fx = Fixture::build();
    let sink = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt-people", 1, None));
    let config = fx.config();
    let mut engine = CaptureEngine::open(config.clone(), None).unwrap();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 1,
        })
        .unwrap();
    engine
        .shipper(sink.clone(), registrar.clone())
        .ship_pending()
        .unwrap();

    // The listing a snap walks holds no excluded path, under any person.
    let roots = ClassRoots {
        root: fx.root.clone(),
        harness_home: Some(fx.home.clone()),
        bulk_dirs: config.bulk_dirs.clone(),
        staging_dir: config.staging_dir(),
    };
    let listing = roots
        .workspace_listing(&GitRepo::open(&fx.root).unwrap(), &[])
        .unwrap();
    for person in PEOPLE {
        for path in SAVED {
            let v = format!("harness/people/{person}/{path}");
            assert!(listing.entries.contains_key(&v), "{v} is not listed");
        }
        for path in never_saved() {
            let v = format!("harness/people/{person}/{path}");
            assert!(!listing.entries.contains_key(&v), "{v} is listed");
        }
    }
    assert!(!listing.entries.contains_key("harness/.codex/auth.json"));

    let restore = fx.base.join("restore");
    let home2 = fx.base.join("home2");
    let head = registrar.head().unwrap();
    Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&restore, Some(home2.clone())),
    )
    .materialize(&head.manifest, MaterializeClass::All)
    .unwrap();
    for person in PEOPLE {
        let p = home2.join("people").join(person);
        for path in SAVED {
            assert_eq!(
                fs::read_to_string(p.join(path)).unwrap(),
                person,
                "{person}/{path}"
            );
        }
        for path in never_saved() {
            assert!(
                fs::symlink_metadata(p.join(&path)).is_err(),
                "{person}/{path} came back"
            );
        }
    }
    assert!(fs::symlink_metadata(home2.join(".codex/auth.json")).is_err());
    assert!(home2.join(".codex/config.toml").exists());
}

/// A capture made before this rule holds a regular `auth.json` and a Codex `-shm` in a person's
/// saved directory: a restore writes back neither, and restores everything beside them.
#[test]
fn a_legacy_capture_s_login_in_a_person_s_directory_is_never_restored() {
    const T: i128 = 1_700_000_000_000_000_000;
    let fx = Fixture::build();
    let sink = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt-people", 1, None));
    let mut engine = CaptureEngine::open(fx.config(), None).unwrap();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 1,
        })
        .unwrap();
    engine
        .shipper(sink.clone(), registrar.clone())
        .ship_pending()
        .unwrap();
    let mut manifest = registrar.head().unwrap().manifest;

    let put = |dir: DirObject| -> String {
        let encoded = dir.encode();
        let key = format!("captures/wt-people/1/trees/{}", encoded.sha256);
        sink.put_if_absent(&key, BlobSource::Bytes(&encoded.bytes))
            .unwrap();
        key
    };
    let codex = put(DirObject::new(vec![
        DirEntry::file("auth.json", 0o600, 0, T, vec![]),
        DirEntry::file("auth.json.mend-seed-3", 0o600, 0, T, vec![]),
        DirEntry::file("config.toml", 0o644, 0, T, vec![]),
    ]));
    let codex_db = put(DirObject::new(vec![
        DirEntry::file("logs_2.sqlite", 0o644, 0, T, vec![]),
        DirEntry::file("state_5.sqlite", 0o644, 0, T, vec![]),
        DirEntry::file("state_5.sqlite-shm", 0o644, 0, T, vec![]),
        DirEntry::file("state_5.sqlite-wal", 0o644, 0, T, vec![]),
    ]));
    let alice = put(DirObject::new(vec![
        DirEntry::dir(".codex", 0o755, T, codex),
        DirEntry::dir("codex-db", 0o755, T, codex_db),
    ]));
    let people = put(DirObject::new(vec![DirEntry::dir(
        "acct_alice",
        0o710,
        T,
        alice,
    )]));
    let harness = put(DirObject::new(vec![DirEntry::dir(
        "people", 0o755, T, people,
    )]));
    let root = put(DirObject::new(vec![DirEntry::dir(
        "harness", 0o755, T, harness,
    )]));
    manifest.sections.workspace = WorkspaceSection::objects(root, Vec::new());

    let home2 = fx.base.join("home-legacy");
    Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&fx.base.join("restore-legacy"), Some(home2.clone())),
    )
    .materialize(&manifest, MaterializeClass::Workspace)
    .unwrap();
    let p = home2.join("people/acct_alice");
    assert!(p.join(".codex/config.toml").exists());
    assert!(p.join("codex-db/state_5.sqlite").exists());
    assert!(p.join("codex-db/state_5.sqlite-wal").exists());
    for gone in [
        ".codex/auth.json",
        ".codex/auth.json.mend-seed-3",
        "codex-db/logs_2.sqlite",
        "codex-db/state_5.sqlite-shm",
    ] {
        assert!(
            fs::symlink_metadata(p.join(gone)).is_err(),
            "{gone} came back"
        );
    }
}
