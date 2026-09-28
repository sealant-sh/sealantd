//! Opening capture never consumes a user file named like its git staging file (review
//! 2026-09-28, seventeenth pass, #2).
//!
//! Capture opening adds the daemon's staging directory to the repository's local excludes
//! (`.git/info/exclude`). It staged the new file through the fixed name
//! `.git/info/exclude.capture-tmp`, opened with truncation, and renamed it over `info/exclude`:
//! a user file of that name was overwritten and then renamed away, at the first open and again
//! when a restarted executor reopened a disk whose sealed capture held the file, and the next
//! final flush sealed the disk without it. The exclude is now staged in a file of its own
//! (`longpath::create_temp`), and a name already there is never opened.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, MaterializeClass,
    MaterializeTargets, Materializer,
};

const EXECUTOR: &str = "exec-r17";

/// The user's own file at the name the exclude update used to stage through.
const USER_FILE: &str = ".git/info/exclude.capture-tmp";

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
    /// `node_modules/`.
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("a"), b"base\n").unwrap();
        fs::write(root.join(".gitignore"), b"node_modules/\n").unwrap();
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

    fn runner_from(&self, engine: CaptureEngine) -> CadenceRunner {
        let shipper = Arc::new(engine.shipper(self.store.clone(), self.registrar.clone()));
        CadenceRunner::new(engine, shipper)
    }

    fn runner(&self) -> CadenceRunner {
        self.runner_from(CaptureEngine::open(self.config(), None).unwrap())
    }

    /// No staging file of the exclude update is left in `.git/info`.
    fn assert_no_staging_left(&self) {
        let left: Vec<String> = fs::read_dir(self.root.join(".git/info"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".exclude.capture-tmp"))
            .collect();
        assert!(left.is_empty(), "staging files left behind: {left:?}");
    }
}

/// A user file at `.git/info/exclude.capture-tmp` survives the first open, byte for byte, and
/// the daemon's exclude is added all the same.
#[test]
fn opening_capture_keeps_a_user_file_at_the_exclude_staging_name() {
    let fx = Fixture::new();
    let path = fx.root.join(USER_FILE);
    let bytes = b"unique user git-local notes\n";
    fs::write(&path, bytes).unwrap();

    let result = fx.runner().flush_final(None);
    assert!(result.complete(), "{result:?}");
    assert_eq!(
        fs::read(&path).ok().as_deref(),
        Some(bytes.as_slice()),
        "opening capture keeps the user's file"
    );
    let exclude = fs::read_to_string(fx.root.join(".git/info/exclude")).unwrap();
    assert!(exclude.contains("/.sealantd/"), "{exclude}");
    fx.assert_no_staging_left();
}

/// A restarted executor reopening a disk whose sealed capture holds the user file (and whose
/// `info/exclude` the user rewrote, so the daemon's line is added again) keeps it; the next
/// final flush seals a disk that still has it, and a cold restore of that seal brings it back.
#[test]
fn reopening_capture_keeps_a_saved_user_file_at_the_exclude_staging_name() {
    let fx = Fixture::new();
    let runner = fx.runner();
    let path = fx.root.join(USER_FILE);
    let bytes = b"unique user git-local notes saved before restart\n";
    fs::write(&path, bytes).unwrap();
    let user_exclude = b"# User-maintained local excludes\n*.local-only\n";
    fs::write(fx.root.join(".git/info/exclude"), user_exclude).unwrap();
    let result = runner.flush_final(None);
    assert!(result.complete(), "before the restart: {result:?}");
    assert_eq!(fs::read(&path).unwrap(), bytes);

    let head = fx.registrar.head().unwrap();
    let previous = Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&fx.root, None))
        .fetch_manifest(&head.manifest_key, &head.capture_id)
        .unwrap();
    drop(runner);
    let restarted = fx.runner_from(CaptureEngine::open(fx.config(), Some(previous)).unwrap());
    assert_eq!(
        fs::read(&path).ok().as_deref(),
        Some(bytes.as_slice()),
        "reopening capture keeps the saved user file"
    );
    let exclude = fs::read(fx.root.join(".git/info/exclude")).unwrap();
    assert!(
        exclude.starts_with(user_exclude),
        "the user's own lines stay first"
    );
    fx.assert_no_staging_left();

    let after = restarted.flush_final(None);
    assert!(after.complete(), "after the restart: {after:?}");
    assert_eq!(fs::read(&path).unwrap(), bytes);

    let out = fx.tmp.path().join("cold");
    Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&out, None))
        .materialize(
            &fx.registrar.head().unwrap().manifest,
            MaterializeClass::All,
        )
        .expect("a cold restore of the sealed capture");
    assert_eq!(
        fs::read(out.join(USER_FILE)).ok().as_deref(),
        Some(bytes.as_slice()),
        "the cold restore holds the user file"
    );
}
