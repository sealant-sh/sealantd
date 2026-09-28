//! What a sealed final flush holds is what the disk held, or the flush is not complete (review
//! 2026-09-28, eighth pass):
//!
//! - a configured root that is a symlink to a directory — `.git`, the harness home — is read
//!   through the link, and a root that is no directory at all is unreadable, never an empty
//!   listing (#1);
//! - a symlinked `FETCH_HEAD` or operation document is read as git reads it (through the link),
//!   and the objects it names are in the packs; one that cannot be read leaves the flush
//!   incomplete (#2);
//! - a symlink inode with more than one name cannot come back as one inode, and a final flush
//!   over one is not complete (#3, decision 23);
//! - a SHA-256 repository restores as one, and a SHA-1 one as before (#10);
//! - a final flush is complete only once the registrar says it recorded the seal and the seal
//!   stands (decision 22).

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, MaterializeClass,
    MaterializeTargets, Materializer,
};

const EXECUTOR: &str = "exec-r8";

fn git_out(root: &Path, args: &[&str], input: Option<&[u8]>) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("git");
    let mut stdin = child.stdin.take().unwrap();
    if let Some(input) = input {
        stdin.write_all(input).unwrap();
    }
    drop(stdin);
    child.wait_with_output().unwrap()
}

fn git(root: &Path, args: &[&str]) -> String {
    git_in(root, args, None)
}

fn git_in(root: &Path, args: &[&str], input: Option<&[u8]>) -> String {
    let out = git_out(root, args, input);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// A commit no ref, reflog or `HEAD` reaches, holding one file with `contents`.
fn unreachable_commit(root: &Path, contents: &[u8]) -> String {
    let blob = git_in(root, &["hash-object", "-w", "--stdin"], Some(contents));
    let tree = git_in(
        root,
        &["mktree"],
        Some(format!("100644 blob {blob}\tunique.txt\n").as_bytes()),
    );
    git(
        root,
        &["commit-tree", &tree, "-m", "unique unreachable commit"],
    )
}

struct Fixture {
    tmp: tempfile::TempDir,
    root: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    /// A repository with one commit on `main`: `a` holding `base\n`; `.gitignore` ignoring
    /// `ignored/` and `node_modules/`.
    fn new() -> Self {
        Self::with_format(None)
    }

    fn with_format(format: Option<&str>) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        let mut init = vec!["init", "-q", "-b", "main"];
        let flag = format.map(|f| format!("--object-format={f}"));
        if let Some(flag) = &flag {
            init.push(flag);
        }
        git(&root, &init);
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

    fn runner(&self, config: CaptureConfig) -> CadenceRunner {
        let engine = CaptureEngine::open(config, None).unwrap();
        let shipper = Arc::new(engine.shipper(self.store.clone(), self.registrar.clone()));
        CadenceRunner::new(engine, shipper)
    }

    /// A final flush that must say `complete` and seal the chain.
    fn final_flush(&self, config: CaptureConfig) {
        let result = self.runner(config).flush_final(None);
        assert!(result.complete(), "{result:?}");
        let head = self.registrar.head().unwrap();
        assert!(head.manifest.final_seal.is_some(), "the chain is sealed");
        assert!(
            !self.registrar.seals().is_empty(),
            "the registrar recorded it"
        );
    }

    /// A final flush that must not say `complete`; its reason and error text.
    fn incomplete_flush(&self, config: CaptureConfig) -> (String, String) {
        let result = self.runner(config).flush_final(None);
        let incomplete = result
            .incomplete
            .clone()
            .unwrap_or_else(|| panic!("the final flush said complete: {result:?}"));
        (incomplete.reason().to_owned(), incomplete.to_string())
    }

    fn restore(&self, name: &str, harness: Option<PathBuf>) -> PathBuf {
        let out = self.tmp.path().join(name);
        Materializer::new(self.store.as_ref(), MaterializeTargets::new(&out, harness))
            .materialize(
                &self.registrar.head().unwrap().manifest,
                MaterializeClass::All,
            )
            .unwrap();
        out
    }
}

// ---------------------------------------------------------------------------------------------
// #1: symlinked roots.
// ---------------------------------------------------------------------------------------------

/// `.git` moved beside the worktree and symlinked back: git reads the repository through the
/// link, and so does the capture — the in-progress merge message and the repository's config
/// come back.
#[test]
fn a_symlinked_git_directory_keeps_its_bookkeeping() {
    let fx = Fixture::new();
    fs::write(
        fx.root.join(".git/MERGE_MSG"),
        b"unique in-progress merge message\n",
    )
    .unwrap();
    git(&fx.root, &["config", "sealant.review", "eight"]);
    let config_before = fs::read(fx.root.join(".git/config")).unwrap();
    let real = fx.tmp.path().join("real-git");
    fs::rename(fx.root.join(".git"), &real).unwrap();
    symlink(&real, fx.root.join(".git")).unwrap();
    git(&fx.root, &["status", "--porcelain"]);

    fx.final_flush(fx.config());
    let out = fx.restore("restored", None);
    assert_eq!(
        fs::read(out.join(".git/MERGE_MSG")).ok(),
        Some(b"unique in-progress merge message\n".to_vec()),
        "the sealed capture lost git's bookkeeping behind a symlinked .git"
    );
    assert_eq!(fs::read(out.join(".git/config")).unwrap(), config_before);
    assert_eq!(git(&out, &["config", "sealant.review"]), "eight");
    assert_eq!(fs::read(out.join("a")).unwrap(), b"base\n");
}

/// The harness home configured as a symlink to a directory: its work comes back in the
/// restore's harness destination, and its credential files are still left out.
#[test]
fn a_symlinked_harness_home_keeps_its_work() {
    let fx = Fixture::new();
    let real = fx.tmp.path().join("real-harness");
    let link = fx.tmp.path().join("linked-harness");
    fs::create_dir_all(real.join(".claude")).unwrap();
    fs::write(
        real.join("session.jsonl"),
        b"unique harness conversation and work\n",
    )
    .unwrap();
    fs::write(real.join(".claude/.credentials.json"), b"secret").unwrap();
    symlink(&real, &link).unwrap();
    let mut config = fx.config();
    config.harness_home = Some(link);

    fx.final_flush(config);
    let home = fx.tmp.path().join("restored-harness");
    fx.restore("restored", Some(home.clone()));
    assert_eq!(
        fs::read(home.join("session.jsonl")).ok(),
        Some(b"unique harness conversation and work\n".to_vec()),
        "the sealed capture lost the harness's work behind its symlinked home"
    );
    assert!(
        !home.join(".claude/.credentials.json").exists(),
        "a credential file travelled through the link"
    );
}

/// A harness home that is a file (directly or through a link) cannot be carried as the
/// directory the class holds: the final flush says so, never a complete flush over nothing.
#[test]
fn a_root_that_is_not_a_directory_leaves_the_final_flush_incomplete() {
    for linked in [false, true] {
        let fx = Fixture::new();
        let file = fx.tmp.path().join("harness-file");
        fs::write(&file, b"work in a file where a directory was configured\n").unwrap();
        let home = if linked {
            let link = fx.tmp.path().join("linked-harness");
            symlink(&file, &link).unwrap();
            link
        } else {
            file
        };
        let mut config = fx.config();
        config.harness_home = Some(home);
        let (reason, error) = fx.incomplete_flush(config);
        println!("linked={linked}: {reason}: {error}");
        assert_eq!(reason, "unreadable", "{error}");
        assert!(error.contains("harness"), "{error}");
        assert!(fx.registrar.seals().is_empty());
    }
}

// ---------------------------------------------------------------------------------------------
// #2: symlinked operation documents.
// ---------------------------------------------------------------------------------------------

/// `FETCH_HEAD` a relative symlink to a file inside `.git` naming a commit nothing else
/// reaches: the commit and its unique file content come back with it.
#[test]
fn a_symlinked_fetch_head_keeps_the_commit_it_names() {
    let fx = Fixture::new();
    let oid = unreachable_commit(
        &fx.root,
        b"unique work reachable only from fetched commit\n",
    );
    fs::create_dir(fx.root.join(".git/held")).unwrap();
    fs::write(
        fx.root.join(".git/held/fetched"),
        format!("{oid}\t\tbranch 'feature' of local\n"),
    )
    .unwrap();
    symlink("held/fetched", fx.root.join(".git/FETCH_HEAD")).unwrap();
    git(&fx.root, &["cat-file", "-e", "FETCH_HEAD^{commit}"]);

    fx.final_flush(fx.config());
    let out = fx.restore("restored", None);
    assert_eq!(
        fs::read_link(out.join(".git/FETCH_HEAD")).unwrap(),
        Path::new("held/fetched")
    );
    let restored = git_out(&out, &["cat-file", "-e", "FETCH_HEAD^{commit}"], None);
    assert!(
        restored.status.success(),
        "the capture kept FETCH_HEAD but lost the commit it names: {restored:?}"
    );
    assert_eq!(
        git(&out, &["show", "FETCH_HEAD:unique.txt"]),
        "unique work reachable only from fetched commit"
    );
}

/// A pending pseudo-ref (`MERGE_HEAD`) and an operation directory's document
/// (`sequencer/abort-safety`) as symlinks: the commits they name come back.
#[test]
fn symlinked_operation_documents_keep_the_commits_they_name() {
    let fx = Fixture::new();
    let merge = unreachable_commit(&fx.root, b"unique work of the merge in progress\n");
    let seq = unreachable_commit(&fx.root, b"unique work the sequencer names\n");
    fs::create_dir(fx.root.join(".git/held")).unwrap();
    fs::write(fx.root.join(".git/held/merge"), format!("{merge}\n")).unwrap();
    fs::write(fx.root.join(".git/held/seq"), format!("{seq}\n")).unwrap();
    symlink("held/merge", fx.root.join(".git/MERGE_HEAD")).unwrap();
    fs::create_dir(fx.root.join(".git/sequencer")).unwrap();
    symlink("../held/seq", fx.root.join(".git/sequencer/abort-safety")).unwrap();

    fx.final_flush(fx.config());
    let out = fx.restore("restored", None);
    for (oid, text) in [
        (&merge, "unique work of the merge in progress"),
        (&seq, "unique work the sequencer names"),
    ] {
        assert_eq!(
            git(&out, &["show", &format!("{oid}:unique.txt")]),
            text,
            "the capture lost a commit a symlinked operation document names"
        );
    }
}

/// A symlinked `FETCH_HEAD` that git cannot read (it names a directory): what it names is
/// unknown, and a final flush does not say it holds the operation's objects.
#[test]
fn an_unreadable_symlinked_fetch_head_leaves_the_final_flush_incomplete() {
    let fx = Fixture::new();
    fs::create_dir(fx.root.join(".git/held")).unwrap();
    symlink("held", fx.root.join(".git/FETCH_HEAD")).unwrap();
    let (reason, error) = fx.incomplete_flush(fx.config());
    println!("{reason}: {error}");
    assert!(error.contains("FETCH_HEAD"), "{error}");
    assert!(fx.registrar.seals().is_empty());
}

// ---------------------------------------------------------------------------------------------
// #3: symlink inodes with several names.
// ---------------------------------------------------------------------------------------------

/// Two names of one symlink inode — in the worktree tree, in an ignored directory (the
/// workspace class), in `node_modules` (the bulk class), and across classes: no class can
/// carry one inode for them, so a final flush is not complete and names the path.
#[test]
fn a_symlink_inode_with_two_names_leaves_the_final_flush_incomplete() {
    let cases: [(&str, &str, &str); 4] = [
        ("tracked", "link-a", "link-b"),
        ("ignored", "ignored/link-a", "ignored/link-b"),
        ("bulk", "node_modules/link-a", "node_modules/link-b"),
        ("cross-class", "ignored/link-a", "node_modules/link-b"),
    ];
    for (case, a, b) in cases {
        let fx = Fixture::new();
        fs::create_dir_all(fx.root.join("ignored")).unwrap();
        fs::create_dir_all(fx.root.join("node_modules")).unwrap();
        symlink("target", fx.root.join(a)).unwrap();
        fs::hard_link(fx.root.join(a), fx.root.join(b)).unwrap();
        let (ma, mb) = (
            fs::symlink_metadata(fx.root.join(a)).unwrap(),
            fs::symlink_metadata(fx.root.join(b)).unwrap(),
        );
        assert!(ma.is_symlink() && ma.ino() == mb.ino() && ma.nlink() == 2);
        let (reason, error) = fx.incomplete_flush(fx.config());
        println!("{case}: {reason}: {error}");
        assert!(
            error.contains("link-a") || error.contains("link-b"),
            "{error}"
        );
        assert!(fx.registrar.seals().is_empty(), "{case}");
    }
}

// ---------------------------------------------------------------------------------------------
// #10: object formats.
// ---------------------------------------------------------------------------------------------

/// A SHA-256 repository with committed work, an uncommitted change and an untracked file: the
/// restore is a SHA-256 repository at the same commit, with every byte back.
#[test]
fn a_sha256_repository_restores_as_one() {
    round_trip(Some("sha256"), "sha256");
}

/// A SHA-1 repository restores as before.
#[test]
fn a_sha1_repository_restores_as_one() {
    round_trip(None, "sha1");
}

fn round_trip(format: Option<&str>, expected: &str) {
    let fx = Fixture::with_format(format);
    fs::write(fx.root.join("work.txt"), b"committed user work\n").unwrap();
    git(&fx.root, &["add", "work.txt"]);
    git(&fx.root, &["commit", "-qm", "user commit"]);
    fs::write(fx.root.join("a"), b"uncommitted change\n").unwrap();
    fs::write(fx.root.join("untracked.txt"), b"untracked work\n").unwrap();
    let head = git(&fx.root, &["rev-parse", "HEAD"]);
    assert_eq!(
        git(&fx.root, &["rev-parse", "--show-object-format"]),
        expected
    );

    fx.final_flush(fx.config());
    let out = fx.restore("restored", None);
    assert_eq!(git(&out, &["rev-parse", "--show-object-format"]), expected);
    assert_eq!(git(&out, &["rev-parse", "HEAD"]), head);
    assert_eq!(git(&out, &["show", "HEAD:work.txt"]), "committed user work");
    assert_eq!(
        fs::read(out.join("work.txt")).unwrap(),
        b"committed user work\n"
    );
    assert_eq!(fs::read(out.join("a")).unwrap(), b"uncommitted change\n");
    assert_eq!(
        fs::read(out.join("untracked.txt")).unwrap(),
        b"untracked work\n"
    );
    git(&out, &["fsck", "--no-dangling"]);
}

// ---------------------------------------------------------------------------------------------
// Decision 22: complete only once the registrar recorded a standing seal.
// ---------------------------------------------------------------------------------------------

/// A registrar that acknowledges the sealing capture without recording its seal (here: it
/// was not issued for this executor): the final flush is not complete, and says `sealing`.
#[test]
fn a_register_that_did_not_record_the_seal_is_not_complete() {
    let mut fx = Fixture::new();
    fx.registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let (reason, error) = fx.incomplete_flush(fx.config());
    println!("{reason}: {error}");
    assert_eq!(reason, "sealing", "{error}");
    assert!(fx.registrar.seals().is_empty());
}

/// The link a symlinked root was reached through is named in the workspace section.
#[test]
fn a_symlinked_root_is_named_with_its_link() {
    let fx = Fixture::new();
    let real = fx.tmp.path().join("real-git");
    fs::rename(fx.root.join(".git"), &real).unwrap();
    symlink(&real, fx.root.join(".git")).unwrap();
    let home_real = fx.tmp.path().join("real-harness");
    fs::create_dir(&home_real).unwrap();
    fs::write(home_real.join("session.jsonl"), b"work\n").unwrap();
    let home = fx.tmp.path().join("linked-harness");
    symlink("real-harness", &home).unwrap();
    let mut config = fx.config();
    config.harness_home = Some(home);
    fx.final_flush(config);
    let links = fx
        .registrar
        .head()
        .unwrap()
        .manifest
        .sections
        .workspace
        .root_links;
    println!("{links:?}");
    assert_eq!(
        links.get(".git").map(String::as_str),
        Some(real.to_str().unwrap())
    );
    assert_eq!(
        links.get("harness").map(String::as_str),
        Some("real-harness")
    );
}

/// A repository whose objects are SHA-256 names its format in the git section; a SHA-1 one
/// names none, so its section encodes as before.
#[test]
fn the_git_section_names_a_format_that_is_not_sha1() {
    for (format, expected) in [(Some("sha256"), Some("sha256")), (None, None)] {
        let fx = Fixture::with_format(format);
        fx.final_flush(fx.config());
        let head = fx.registrar.head().unwrap();
        assert_eq!(
            head.manifest.sections.git.object_format.as_deref(),
            expected
        );
        let text = String::from_utf8(head.manifest.clone().encode().bytes).unwrap();
        assert_eq!(text.contains("object_format"), expected.is_some(), "{text}");
    }
}

/// A store that does not read `object_format`: a SHA-256 repository's final flush is not
/// complete (the store would restore it as SHA-1), a SHA-1 one's is.
#[test]
fn a_store_that_does_not_read_the_object_format_cannot_complete_a_sha256_flush() {
    let reads: Vec<String> = sealant_capture::registrar::MANIFEST_FEATURES
        .iter()
        .filter(|f| **f != "object_format")
        .map(|f| (*f).to_owned())
        .collect();
    let fx = Fixture::with_format(Some("sha256"));
    let mut config = fx.config();
    config.set_store_features(&reads);
    assert!(
        config.fidelity_gap().is_none(),
        "a SHA-1 repository needs nothing more"
    );
    let (reason, error) = fx.incomplete_flush(config);
    println!("{reason}: {error}");
    assert!(error.contains("object_format"), "{error}");
    assert!(fx.registrar.seals().is_empty());

    let fx = Fixture::new();
    let mut config = fx.config();
    config.set_store_features(&reads);
    fx.final_flush(config);
}

/// The registrar withholds the seal (still verifying what it names): the final flush asks
/// again, and is complete once the answer is `recorded`.
#[test]
fn a_withheld_seal_is_asked_again_until_it_stands() {
    let fx = Fixture::new();
    fx.registrar.withhold_seals(2);
    fx.final_flush(fx.config());
    assert_eq!(fx.registrar.seals().len(), 1);
}

/// A seal withheld past every ask: the final flush is not complete and says `sealing`, the
/// runner does not say it sealed, and a final flush asked again once the registrar lets it
/// stand is complete.
#[test]
fn a_seal_still_withheld_leaves_the_final_flush_incomplete() {
    let fx = Fixture::new();
    fx.registrar.withhold_seals(1_000);
    let runner = fx.runner(fx.config());
    let result = runner.flush_final(None);
    let incomplete = result.incomplete.clone().expect("not complete");
    println!("{incomplete}");
    assert_eq!(incomplete.reason(), "sealing");
    assert!(incomplete.to_string().contains("withheld"), "{incomplete}");
    assert!(!runner.final_sealed());
    assert!(fx.registrar.seals().is_empty());
    assert!(
        fx.registrar.head().unwrap().manifest.final_seal.is_some(),
        "the sealing capture registered"
    );
    fx.registrar.withhold_seals(0);
    let again = runner.flush_final(None);
    assert!(again.complete(), "{again:?}");
    assert!(runner.final_sealed());
    assert_eq!(fx.registrar.seals().len(), 1);
}

/// A registrar that answers no `seal` (from before decision 22): never complete.
#[test]
fn a_registrar_that_does_not_say_where_the_seal_stands_is_not_complete() {
    let fx = Fixture::new();
    fx.registrar.without_seal_answers();
    let (reason, error) = fx.incomplete_flush(fx.config());
    println!("{reason}: {error}");
    assert_eq!(reason, "sealing");
    assert!(error.contains("did not say"), "{error}");
}

/// A daemon that restarted over a sealed chain asks where the seal stands before it answers
/// complete: a new runner's final flush over the same staging asks the registrar again.
#[test]
fn a_new_runner_over_a_sealed_chain_asks_where_the_seal_stands() {
    let fx = Fixture::new();
    fx.final_flush(fx.config());
    let registers = fx.registrar.chain().len();
    fx.registrar.withhold_seals(1_000);
    let head = fx.registrar.head().unwrap().manifest.encode();
    let engine = CaptureEngine::open(fx.config(), Some(head)).unwrap();
    let shipper = Arc::new(engine.shipper(fx.store.clone(), fx.registrar.clone()));
    let result = CadenceRunner::new(engine, shipper).flush_final(None);
    println!("{result:?}");
    assert_eq!(
        result
            .incomplete
            .as_ref()
            .map(sealant_capture::Incomplete::reason),
        Some("sealing"),
    );
    assert_eq!(
        fx.registrar.chain().len(),
        registers,
        "nothing new registered"
    );
}

/// A symlinked `.git` is watched through its link: a write to its bookkeeping after a complete
/// final flush is seen, and the flush is no longer current.
#[test]
fn a_symlinked_git_directory_is_watched_through_its_link() {
    for linked in [false, true] {
        watched(linked);
    }
}

fn watched(linked: bool) {
    let fx = Fixture::new();
    if linked {
        let real = fx.tmp.path().join("real-git");
        fs::rename(fx.root.join(".git"), &real).unwrap();
        symlink(&real, fx.root.join(".git")).unwrap();
    }
    let runner = fx.runner(fx.config());
    // The daemon's admission hook: no writer runs any more, so no scheduled snap either.
    runner.start(Some(Arc::new(|| false)));
    let result = runner.flush_final(None);
    assert!(result.complete(), "{result:?}");
    assert!(
        runner.final_is_current(),
        "watched and unchanged: {:?}",
        runner.snapshot()
    );
    fs::write(fx.root.join(".git/MERGE_MSG"), b"written after the seal\n").unwrap();
    let start = std::time::Instant::now();
    while runner.final_is_current() {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "linked={linked}: a write behind .git is never seen: {:?}",
            runner.snapshot()
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    runner.stop();
}
