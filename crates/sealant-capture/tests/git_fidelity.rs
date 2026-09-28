//! What a complete, sealed final flush holds of the repository comes back exactly (review
//! 2026-09-28, third pass): `HEAD` pointing at a symbolic ref stays pointed at it (#11); a user
//! ref under `refs/sealant/capture/` is the user's (#12); every object `FETCH_HEAD`, `ORIG_HEAD`,
//! `MERGE_HEAD`, a rebase or a bisect names is in the packs (#4); the working tree's bytes are the
//! bytes on disk, whatever git's attributes would clean or smudge (#10); and a nested repository
//! whose name is not UTF-8 is carried whole (#3). Each fixture's final flush must say `complete`
//! and leave a `final_seal` on the chain; the restore is a fresh materialize of that head.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, MaterializeClass,
    MaterializeTargets, Materializer,
};

fn git_raw(root: &Path, args: &[&OsStr]) -> Output {
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
    out
}

fn git(root: &Path, args: &[&str]) -> String {
    let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let out = git_raw(root, &args);
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn git_ok(root: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git")
        .status
        .success()
}

/// The target `name` names itself (`--no-recurse`).
fn symbolic_ref(root: &Path, name: &str) -> String {
    git(root, &["symbolic-ref", "--no-recurse", name])
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    out: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("one");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("a"), b"base").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "base"]);
        Self {
            out: temp.path().join("out"),
            store: Arc::new(LocalDir::new(&temp.path().join("store")).unwrap()),
            registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None).with_executor("exec-r3")),
            root,
            _temp: temp,
        }
    }

    /// A final flush that must say `complete` and seal the chain, then a fresh restore of the
    /// head.
    fn final_flush_and_restore(&self) {
        let mut config = CaptureConfig::new("wt", 1, &self.root);
        config.executor = Some("exec-r3".to_owned());
        let engine = CaptureEngine::open(config, None).unwrap();
        let shipper = Arc::new(engine.shipper(self.store.clone(), self.registrar.clone()));
        let runner = CadenceRunner::new(engine, shipper);
        let result = runner.flush_final(None);
        assert!(result.complete(), "{result:?}");
        let head = self.registrar.head().unwrap();
        assert!(head.manifest.final_seal.is_some());
        assert!(!self.registrar.seals().is_empty());
        Materializer::new(
            self.store.as_ref(),
            MaterializeTargets::new(&self.out, None),
        )
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    }

    /// A commit no ref and no reflog reaches.
    fn loose_commit(&self, message: &str) -> String {
        git(
            &self.root,
            &["commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", message],
        )
    }

    /// A commit only `name` reaches (no reflog).
    fn ref_with_own_commit(&self, name: &str, message: &str) -> String {
        let oid = self.loose_commit(message);
        git(
            &self.root,
            &[
                "-c",
                "core.logAllRefUpdates=false",
                "update-ref",
                name,
                &oid,
            ],
        );
        oid
    }
}

/// `HEAD -> refs/heads/alias -> refs/heads/main` comes back as it was: `HEAD` names `alias`, not
/// the branch `alias` resolves to (it came back as `refs/heads/main`: `git symbolic-ref -q HEAD`
/// follows the chain).
#[test]
fn a_symbolic_head_chain_keeps_its_first_link() {
    let fx = Fixture::new();
    git(
        &fx.root,
        &["symbolic-ref", "refs/heads/alias", "refs/heads/main"],
    );
    git(&fx.root, &["symbolic-ref", "HEAD", "refs/heads/alias"]);
    assert_eq!(symbolic_ref(&fx.root, "HEAD"), "refs/heads/alias");
    fx.final_flush_and_restore();
    assert_eq!(symbolic_ref(&fx.out, "HEAD"), "refs/heads/alias");
    assert_eq!(symbolic_ref(&fx.out, "refs/heads/alias"), "refs/heads/main");
    assert_eq!(
        git(&fx.out, &["rev-parse", "HEAD"]),
        git(&fx.root, &["rev-parse", "HEAD"])
    );
}

/// Refs under `refs/sealant/capture/` are the user's like any other — including the two names
/// the capture once used for its own worktree and index trees. Before, a restore dropped every
/// ref under that prefix, and the commit only it reached was left unreachable.
#[test]
fn user_refs_under_the_capture_namespace_are_restored() {
    let fx = Fixture::new();
    let names = [
        "refs/sealant/capture/my-work",
        "refs/sealant/capture/worktree",
        "refs/sealant/capture/index",
    ];
    let oids: Vec<String> = names
        .iter()
        .map(|n| fx.ref_with_own_commit(n, &format!("work on {n}")))
        .collect();
    fs::write(fx.root.join("uncommitted"), b"worktree bytes").unwrap();
    fx.final_flush_and_restore();
    for (name, oid) in names.iter().zip(&oids) {
        assert_eq!(
            git(&fx.out, &["rev-parse", "--verify", name]),
            *oid,
            "{name} is not restored with its commit"
        );
    }
    // The working tree is still the one captured, not a user ref's.
    assert_eq!(
        fs::read(fx.out.join("uncommitted")).unwrap(),
        b"worktree bytes"
    );
    assert_eq!(
        git(
            &fx.out,
            &["for-each-ref", "--format=%(refname) %(objectname)"]
        ),
        git(
            &fx.root,
            &["for-each-ref", "--format=%(refname) %(objectname)"]
        )
    );
}

/// A commit only `FETCH_HEAD` names — a real `git fetch <remote> <branch>` with no destination
/// ref — is in the restored repository. Before, `FETCH_HEAD` came back byte for byte naming a
/// commit no pack held.
#[test]
fn a_commit_only_fetch_head_names_is_restored() {
    let fx = Fixture::new();
    let other = fx._temp.path().join("other");
    fs::create_dir_all(&other).unwrap();
    git(&other, &["init", "-q", "-b", "topic"]);
    git(&other, &["config", "user.email", "t@t"]);
    git(&other, &["config", "user.name", "t"]);
    fs::write(other.join("fetched.txt"), b"only upstream has this").unwrap();
    git(&other, &["add", "-A"]);
    git(&other, &["commit", "-qm", "fetched work"]);
    let fetched = git(&other, &["rev-parse", "HEAD"]);
    git(&fx.root, &["fetch", "-q", other.to_str().unwrap(), "topic"]);
    assert!(git_ok(&fx.root, &["cat-file", "-e", "FETCH_HEAD^{commit}"]));
    assert_eq!(git(&fx.root, &["rev-parse", "FETCH_HEAD"]), fetched);
    // Nothing else reaches it.
    assert!(!git(&fx.root, &["for-each-ref", "--contains", &fetched]).contains("refs/"));
    fx.final_flush_and_restore();
    assert_eq!(
        fs::read(fx.root.join(".git/FETCH_HEAD")).unwrap(),
        fs::read(fx.out.join(".git/FETCH_HEAD")).unwrap()
    );
    assert!(
        git_ok(&fx.out, &["cat-file", "-e", &format!("{fetched}^{{tree}}")]),
        "the commit FETCH_HEAD names is not restored"
    );
    assert_eq!(
        git(&fx.out, &["show", "FETCH_HEAD:fetched.txt"]),
        "only upstream has this"
    );
}

/// Every object a pseudo-ref or an operation's state names is restored: `ORIG_HEAD`,
/// `MERGE_HEAD` (two parents), `CHERRY_PICK_HEAD`, `REVERT_HEAD`, `REBASE_HEAD`, `AUTO_MERGE`,
/// `BISECT_HEAD`, `BISECT_EXPECTED_REV`, and a rebase's state directory — its `onto`,
/// `orig-head`, `stopped-sha` and a todo list naming commits by abbreviated id — none of which a
/// ref or reflog reaches.
#[test]
fn objects_named_by_pseudo_refs_and_operation_state_are_restored() {
    let fx = Fixture::new();
    let mut named: Vec<String> = Vec::new();
    for file in [
        "ORIG_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "REBASE_HEAD",
        "BISECT_HEAD",
        "BISECT_EXPECTED_REV",
    ] {
        let oid = fx.loose_commit(&format!("only {file}"));
        fs::write(fx.root.join(".git").join(file), format!("{oid}\n")).unwrap();
        named.push(oid);
    }
    let merge_one = fx.loose_commit("merge parent one");
    let merge_two = fx.loose_commit("merge parent two");
    fs::write(
        fx.root.join(".git/MERGE_HEAD"),
        format!("{merge_one}\n{merge_two}\n"),
    )
    .unwrap();
    named.extend([merge_one, merge_two]);
    // AUTO_MERGE names a tree.
    fs::write(fx.root.join("auto.txt"), b"auto merge result").unwrap();
    git(&fx.root, &["add", "auto.txt"]);
    let tree = git(&fx.root, &["write-tree"]);
    git(&fx.root, &["rm", "-q", "--cached", "auto.txt"]);
    fs::remove_file(fx.root.join("auto.txt")).unwrap();
    fs::write(fx.root.join(".git/AUTO_MERGE"), format!("{tree}\n")).unwrap();
    named.push(tree);
    let rebase = fx.root.join(".git/rebase-merge");
    fs::create_dir_all(&rebase).unwrap();
    for file in ["onto", "orig-head", "stopped-sha"] {
        let oid = fx.loose_commit(&format!("rebase {file}"));
        fs::write(rebase.join(file), format!("{oid}\n")).unwrap();
        named.push(oid);
    }
    let todo_one = fx.loose_commit("todo one");
    let todo_two = fx.loose_commit("todo two");
    fs::write(
        rebase.join("git-rebase-todo"),
        format!(
            "pick {} todo one\nfixup {} todo two\n# a comment deadbeef\n",
            &todo_one[..12],
            &todo_two[..9]
        ),
    )
    .unwrap();
    named.extend([todo_one, todo_two]);
    for oid in &named {
        assert!(git_ok(&fx.root, &["cat-file", "-e", oid]));
    }
    fx.final_flush_and_restore();
    for oid in &named {
        assert!(
            git_ok(&fx.out, &["cat-file", "-e", oid]),
            "{oid} is not restored"
        );
    }
    assert_eq!(
        fs::read(rebase.join("git-rebase-todo")).unwrap(),
        fs::read(fx.out.join(".git/rebase-merge/git-rebase-todo")).unwrap()
    );
}

/// A tracked file with CRLF line ends under `text eol=lf` comes back with CRLF (it came back LF:
/// the capture took the tree `git add` normalized), a file a clean filter rewrites comes back as
/// written, a UTF-16 file under `working-tree-encoding` comes back as UTF-16, an LF file under
/// `eol=crlf` is not given CRLF on the way out, and an `ident` file keeps its expanded keyword.
/// The user's own index and attributes come back as they were: git's view of the restored
/// working tree is the source's.
#[test]
fn working_tree_bytes_survive_git_attributes() {
    let fx = Fixture::new();
    let root = &fx.root;
    git(root, &["config", "filter.shout.clean", "tr a-z A-Z"]);
    git(
        root,
        &["config", "filter.shout.smudge", "sed s/^/SMUDGED:/"],
    );
    fs::write(
        root.join(".gitattributes"),
        "*.txt text eol=lf\n*.shout filter=shout\n*.u16 working-tree-encoding=UTF-16LE text\n*.bat text eol=crlf\n*.id ident\n",
    )
    .unwrap();
    let utf16: Vec<u8> = "héllo\r\nwörld\r\n"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("draft.txt", b"first\r\nsecond\r\n".to_vec()),
        ("quiet.shout", b"whisper\n".to_vec()),
        ("wide.u16", utf16),
        ("run.bat", b"echo lf only\n".to_vec()),
        ("keyword.id", b"$Id$\n".to_vec()),
    ];
    for (name, bytes) in &files {
        fs::write(root.join(name), bytes).unwrap();
    }
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "attributes"]);
    // Committed as git cleaned them; the working tree keeps its own bytes (and `ident` expands).
    for (name, bytes) in &files {
        if *name != "keyword.id" {
            fs::write(root.join(name), bytes).unwrap();
        }
    }
    // An uncommitted edit too, CRLF again.
    fs::write(root.join("draft.txt"), b"first\r\nsecond\r\nthird\r\n").unwrap();
    let keyword = fs::read(root.join("keyword.id")).unwrap();
    let before: Vec<(String, Vec<u8>)> = files
        .iter()
        .map(|(n, _)| ((*n).to_owned(), fs::read(root.join(n)).unwrap()))
        .collect();
    assert_eq!(before[0].1, b"first\r\nsecond\r\nthird\r\n");
    fx.final_flush_and_restore();
    for (name, bytes) in &before {
        assert_eq!(
            &fs::read(fx.out.join(name)).unwrap(),
            bytes,
            "{name}: {:?}",
            String::from_utf8_lossy(&fs::read(fx.out.join(name)).unwrap())
        );
    }
    assert_eq!(fs::read(fx.out.join("keyword.id")).unwrap(), keyword);
    assert_eq!(
        fs::read(fx.out.join(".gitattributes")).unwrap(),
        fs::read(root.join(".gitattributes")).unwrap()
    );
    // The real index: the blobs git cleaned, as the user staged them.
    assert_eq!(
        git(&fx.out, &["ls-files", "-s"]),
        git(root, &["ls-files", "-s"])
    );
    assert_eq!(
        git(&fx.out, &["status", "--porcelain"]),
        git(root, &["status", "--porcelain"])
    );
}

/// A nested repository whose directory name is not UTF-8 is carried whole: its files and its
/// history. Before, its name was decoded lossily, nothing was found at the decoded path, and a
/// complete, sealed final flush restored none of it.
#[test]
fn a_nested_repository_with_a_raw_name_is_restored() {
    let fx = Fixture::new();
    let name = OsStr::from_bytes(b"nested-\xe9");
    let nested = fx.root.join(name);
    fs::create_dir_all(&nested).unwrap();
    git(&nested, &["init", "-q", "-b", "main"]);
    git(&nested, &["config", "user.email", "t@t"]);
    git(&nested, &["config", "user.name", "t"]);
    fs::write(nested.join("unique.txt"), b"nested user work").unwrap();
    git(&nested, &["add", "-A"]);
    git(&nested, &["commit", "-qm", "nested work"]);
    fs::write(nested.join("draft.txt"), b"uncommitted nested work").unwrap();
    let nested_head = git(&nested, &["rev-parse", "HEAD"]);
    fx.final_flush_and_restore();
    let restored = fx.out.join(name);
    assert_eq!(
        fs::read(restored.join("unique.txt")).unwrap(),
        b"nested user work"
    );
    assert_eq!(
        fs::read(restored.join("draft.txt")).unwrap(),
        b"uncommitted nested work"
    );
    assert_eq!(git(&restored, &["rev-parse", "HEAD"]), nested_head);
    // The outer repository still sees it as an untracked nested repository, not a file.
    assert_eq!(
        git(&fx.out, &["status", "--porcelain"]),
        git(&fx.root, &["status", "--porcelain"])
    );
}

/// A registrar that does not read `git_trees` gets the trees as the two pseudo-refs, as before,
/// and the capture still restores; a user ref under `refs/sealant/capture/` other than those two
/// names is restored as the ref it is (a reader drops only the two names it reads as trees).
/// But such a store cannot hold what the capture read — the raw bytes, a user ref named like a
/// pseudo-ref — so its final flush is never complete and seals nothing (review 2026-09-28,
/// fourth pass, #7: it said `complete` over a lossy capture and sealed it).
#[test]
fn a_registrar_without_git_trees_gets_the_pseudo_refs() {
    let fx = Fixture::new();
    let mine = fx.ref_with_own_commit("refs/sealant/capture/my-work", "mine");
    fs::write(fx.root.join("draft.md"), b"uncommitted").unwrap();
    let mut config = CaptureConfig::new("wt", 1, &fx.root);
    config.executor = Some("exec-r3".to_owned());
    config.git_trees = false;
    let engine = CaptureEngine::open(config, None).unwrap();
    let shipper = Arc::new(engine.shipper(fx.store.clone(), fx.registrar.clone()));
    let runner = CadenceRunner::new(engine, shipper);
    let result = runner.flush_final(None);
    assert_eq!(
        result.incomplete.as_ref().map(|i| i.reason()),
        Some("store-fidelity"),
        "{result:?}"
    );
    assert!(
        fx.registrar.seals().is_empty(),
        "a lossy capture is never sealed"
    );
    let head = fx.registrar.head().unwrap();
    assert!(head.manifest.final_seal.is_none());
    let section = &head.manifest.sections.git;
    assert!(section.worktree_tree.is_none() && section.raw_tree.is_none());
    assert!(
        section
            .refs
            .contains_key(sealant_capture::manifest::WORKTREE_TREE_REF)
    );
    assert!(
        section
            .refs
            .contains_key(sealant_capture::manifest::INDEX_TREE_REF)
    );
    Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&fx.out, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(fs::read(fx.out.join("draft.md")).unwrap(), b"uncommitted");
    assert_eq!(
        git(
            &fx.out,
            &["rev-parse", "--verify", "refs/sealant/capture/my-work"]
        ),
        mine
    );
    assert!(!git_ok(
        &fx.out,
        &[
            "rev-parse",
            "--verify",
            "-q",
            "refs/sealant/capture/worktree"
        ]
    ));
}

/// The user's `.git/index` and `.git/config`, byte for byte.
fn index_and_config(root: &Path) -> (Vec<u8>, Vec<u8>) {
    (
        fs::read(root.join(".git/index")).unwrap(),
        fs::read(root.join(".git/config")).unwrap(),
    )
}

/// A tracked file the user marked `assume-unchanged` and then edited is captured as it is on
/// disk (review 2026-09-28, fourth pass, #2). Before, the scratch index was a copy of the user's
/// with the bit set, `git add -A` never looked at the file, and a complete, sealed final flush
/// restored the committed `base`. The user's own index and configuration are not touched, and
/// the restored index carries the bit as the user set it.
#[test]
fn an_assume_unchanged_edit_is_captured() {
    let fx = Fixture::new();
    git(&fx.root, &["update-index", "--assume-unchanged", "a"]);
    fs::write(fx.root.join("a"), b"unique user work outside git status").unwrap();
    let before = index_and_config(&fx.root);
    fx.final_flush_and_restore();
    assert_eq!(
        index_and_config(&fx.root),
        before,
        "the user's index and config"
    );
    assert_eq!(
        fs::read(fx.out.join("a")).unwrap(),
        b"unique user work outside git status"
    );
    assert_eq!(git(&fx.out, &["ls-files", "-v", "a"]), "h a");
    assert_eq!(fs::read(fx.out.join(".git/index")).unwrap(), before.0);
}

/// The same for `skip-worktree` over a file that is on disk (a local configuration file the
/// user keeps out of `git status`). Before, the final flush could not complete at all.
#[test]
fn a_skip_worktree_edit_is_captured() {
    let fx = Fixture::new();
    git(&fx.root, &["update-index", "--skip-worktree", "a"]);
    fs::write(
        fx.root.join("a"),
        b"unique skip-worktree local configuration",
    )
    .unwrap();
    let before = index_and_config(&fx.root);
    fx.final_flush_and_restore();
    assert_eq!(
        index_and_config(&fx.root),
        before,
        "the user's index and config"
    );
    assert_eq!(
        fs::read(fx.out.join("a")).unwrap(),
        b"unique skip-worktree local configuration"
    );
    assert_eq!(git(&fx.out, &["ls-files", "-v", "a"]), "S a");
}

/// `core.ignorecase=true` left in the configuration of a repository on a case-sensitive disk
/// (moved from a case-insensitive one) does not hide a file whose name differs from a tracked
/// one only by case (#2). Before, `git add` took `A` for the tracked `a`, the ignored-files walk
/// did not list it either, and a complete, sealed final flush restored no `A`. The user's
/// configuration keeps its `ignorecase`.
#[test]
fn ignorecase_does_not_hide_a_distinct_file() {
    let fx = Fixture::new();
    git(&fx.root, &["config", "core.ignorecase", "true"]);
    fs::write(
        fx.root.join("A"),
        b"unique uppercase file on a case sensitive disk",
    )
    .unwrap();
    let before = index_and_config(&fx.root);
    fx.final_flush_and_restore();
    assert_eq!(
        index_and_config(&fx.root),
        before,
        "the user's index and config"
    );
    assert_eq!(
        fs::read(fx.out.join("A")).unwrap(),
        b"unique uppercase file on a case sensitive disk"
    );
    assert_eq!(fs::read(fx.out.join("a")).unwrap(), b"base");
    assert_eq!(fs::read(fx.out.join(".git/config")).unwrap(), before.1);
}

/// A rebase todo list naming a commit by a four-digit abbreviation — git's minimum, valid with
/// `core.abbrev=4` or as a user edited the list — has that commit in the packs (#3). Before,
/// only runs of seven or more hex digits were looked up, the commit (no ref, no reflog) was left
/// out, and the restored rebase could not pick it although the final flush was complete.
#[test]
fn a_rebase_todo_naming_a_commit_by_four_digits_is_restored() {
    let fx = Fixture::new();
    let oid = fx.loose_commit("unique work awaiting pick");
    let short = &oid[..4];
    assert_eq!(git(&fx.root, &["rev-parse", short]), oid);
    fs::create_dir_all(fx.root.join(".git/rebase-merge")).unwrap();
    fs::write(
        fx.root.join(".git/rebase-merge/git-rebase-todo"),
        format!("pick {short} unique work awaiting pick\n"),
    )
    .unwrap();
    fx.final_flush_and_restore();
    assert!(
        git_ok(&fx.out, &["cat-file", "-e", &oid]),
        "{oid} is not restored"
    );
    assert_eq!(
        fs::read(fx.out.join(".git/rebase-merge/git-rebase-todo")).unwrap(),
        fs::read(fx.root.join(".git/rebase-merge/git-rebase-todo")).unwrap()
    );
}

/// Four hex digits two objects of the repository share, found by writing blobs until two
/// collide (a few hundred suffice for 65 536 prefixes).
fn ambiguous_prefix(root: &Path) -> String {
    let dir = root.join(".git/blobs-for-a-collision");
    fs::create_dir_all(&dir).unwrap();
    let mut paths = String::new();
    for i in 0..3000 {
        let path = dir.join(i.to_string());
        fs::write(&path, format!("blob {i}\n")).unwrap();
        paths.push_str(&format!("{}\n", path.display()));
    }
    let out = Command::new("git")
        .current_dir(root)
        .args(["hash-object", "-w", "--stdin-paths"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            // From another thread: the ids fill the pipe before the paths are all written.
            let mut stdin = child.stdin.take().unwrap();
            let writer = std::thread::spawn(move || stdin.write_all(paths.as_bytes()));
            let out = child.wait_with_output();
            writer.join().unwrap()?;
            out
        })
        .unwrap();
    fs::remove_dir_all(&dir).unwrap();
    let mut seen = std::collections::HashSet::new();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|oid| oid[..4].to_owned())
        .find(|prefix| !seen.insert(prefix.clone()))
        .expect("two of 3000 blobs share four leading digits")
}

/// A final flush over a paused rebase whose todo list names a commit git cannot resolve to
/// exactly one object — an abbreviation two objects share, or one no object has — is not
/// complete and seals nothing (#3): the capture cannot know what the resumed rebase needs.
#[test]
fn an_unresolvable_rebase_dependency_is_never_complete() {
    for case in ["ambiguous", "missing"] {
        let fx = Fixture::new();
        let word = match case {
            "ambiguous" => ambiguous_prefix(&fx.root),
            _ => (0..=0xffff_u32)
                .map(|n| format!("{n:04x}"))
                .find(|w| !git_ok(&fx.root, &["cat-file", "-e", w]))
                .unwrap(),
        };
        assert!(!git_ok(&fx.root, &["rev-parse", "--verify", "-q", &word]));
        fs::create_dir_all(fx.root.join(".git/rebase-merge")).unwrap();
        fs::write(
            fx.root.join(".git/rebase-merge/git-rebase-todo"),
            format!("# pick 0000 a comment names nothing\nexec true\npick {word} the pick\n"),
        )
        .unwrap();
        let mut config = CaptureConfig::new("wt", 1, &fx.root);
        config.executor = Some("exec-r3".to_owned());
        let engine = CaptureEngine::open(config, None).unwrap();
        let shipper = Arc::new(engine.shipper(fx.store.clone(), fx.registrar.clone()));
        let runner = CadenceRunner::new(engine, shipper);
        let result = runner.flush_final(None);
        assert!(!result.complete(), "{case}: {result:?}");
        assert!(fx.registrar.seals().is_empty(), "{case}: sealed");
        // Free text that only looks like an abbreviation (a commit message) does not count.
        let fx = Fixture::new();
        fs::create_dir_all(fx.root.join(".git/rebase-merge")).unwrap();
        fs::write(
            fx.root.join(".git/rebase-merge/message"),
            format!("fix {word}: a decade of faded beef\n"),
        )
        .unwrap();
        fx.final_flush_and_restore();
    }
}

/// The lossy fallback that review found (#7): `text eol=lf` over a CRLF file, and a user ref
/// under the exact name the old format reads a tree from. The store would restore LF and drop
/// the ref, so the final flush over it is not complete and nothing is sealed — the executor is
/// kept, never stopped as saved. Asked again, it still is not.
#[test]
fn a_lossy_store_never_completes_a_final_flush() {
    let fx = Fixture::new();
    fx.ref_with_own_commit(
        "refs/sealant/capture/worktree",
        "user branch under the old name",
    );
    fs::write(fx.root.join(".gitattributes"), "*.txt text eol=lf\n").unwrap();
    fs::write(fx.root.join("draft.txt"), b"first\r\nsecond\r\n").unwrap();
    let mut config = CaptureConfig::new("wt", 1, &fx.root);
    config.executor = Some("exec-r3".to_owned());
    config.git_trees = false;
    let engine = CaptureEngine::open(config, None).unwrap();
    let shipper = Arc::new(engine.shipper(fx.store.clone(), fx.registrar.clone()));
    let runner = CadenceRunner::new(engine, shipper);
    for _ in 0..2 {
        let result = runner.flush_final(None);
        assert!(!result.complete(), "{result:?}");
        assert!(fx.registrar.seals().is_empty());
        assert!(!runner.final_sealed());
    }
}
