//! Git class: the closure of refs, `HEAD`, index, stash and reflog tips read first, packed with
//! `git pack-objects --revs` against the previous capture's tips as negatives (never `--thin`),
//! indexed with `git index-pack`, checked with `git fsck --connectivity-only`; bounded retries
//! when refs move or an object goes missing mid-pack (ADR-0015 *Snap rules*). Also the
//! materialize-side helpers: install a pack, write `packed-refs` and `HEAD`, check out a tree.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sealant_process::CommandGateExt;
use serde::{Deserialize, Serialize};

use crate::chunk::sha256_hex;
use crate::longpath;
use crate::manifest::FsckStatus;
use crate::tree::{bytes_of, key_of};

/// Bounded attempts when refs move or objects vanish between the read and the pack.
pub const PACK_ATTEMPTS: u32 = 3;

/// Bounded re-runs of `git add` that each set aside one more path git died on.
const FATAL_PATH_RETRIES: usize = 16;

/// The `git add` a worktree tree is written with ([`GitRepo::worktree_add_args`]).
#[derive(Debug, Clone)]
struct AddArgs {
    /// Flags (`add -A --ignore-errors`).
    args: Vec<String>,
    /// Pathspecs, as bytes: `.` and the `:(exclude,literal)` items.
    pathspecs: Vec<Vec<u8>>,
    /// Nested repositories left out (the chunked class carries them), as [`key_of`] keys.
    nested: Vec<String>,
    /// Paths git cannot reach, left out (the chunked class carries them), as keys.
    beyond: Vec<String>,
}

/// `:(exclude,literal)<path>`: a pathspec item that leaves `path` (bytes, exactly; a `*` or `?`
/// in a name is not a pattern) out of an add.
fn exclude_spec(path: &[u8]) -> Vec<u8> {
    let mut spec = b":(exclude,literal)".to_vec();
    spec.extend_from_slice(path);
    spec
}

/// Whether `rel` is `dir` or under it (bytes; `dir` without a trailing `/`).
fn at_or_under(rel: &[u8], dir: &[u8]) -> bool {
    !dir.is_empty()
        && (rel == dir
            || rel
                .strip_prefix(dir)
                .is_some_and(|r| r.first() == Some(&b'/')))
}

/// The files of a git directory (a worktree's own) whose text names objects no ref or reflog
/// may reach: the pseudo-refs a fetch, merge, cherry-pick, revert, rebase, reset or bisect
/// writes, and the state such an operation keeps while it is in progress.
/// An operation document's bytes, read as git reads it: through a symlink wherever it points.
/// `None` when there is none (missing, or a dangling link). Only a regular file is read: one
/// that is something else (a directory, a fifo that would block) cannot be the document git
/// would read, and is an error.
fn read_document(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_file() => match fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        },
        Ok(_) => Err(io::Error::other("not a regular file")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn names_operation_objects(name: &[u8]) -> bool {
    name.ends_with(b"_HEAD")
        || name == b"AUTO_MERGE"
        || name.starts_with(b"BISECT_")
        || name.starts_with(b"MERGE_")
        || name == b"SQUASH_MSG"
}

/// Directories of a git directory that hold an operation's state (a rebase, `am`, a sequence of
/// cherry-picks or reverts): every file under them may name objects.
const OPERATION_DIRS: &[&str] = &["rebase-merge", "rebase-apply", "sequencer"];

/// The pseudo-refs of an operation in progress, each line of which names an object the
/// operation needs to go on (a merge's other parents, the commit a cherry-pick, revert or
/// rebase stopped at, the tree of a merge's result, the commit a bisect checked out).
/// `FETCH_HEAD` and `ORIG_HEAD` outlive every operation and may name objects long pruned: their
/// objects are carried when they resolve, and are not dependencies.
const PENDING_REFS: &[&[u8]] = &[
    b"MERGE_HEAD",
    b"CHERRY_PICK_HEAD",
    b"REVERT_HEAD",
    b"REBASE_HEAD",
    b"AUTO_MERGE",
    b"BISECT_HEAD",
    b"BISECT_EXPECTED_REV",
];

/// The instruction lists of an operation directory (a rebase's todo, its backup and what is
/// done; a sequencer's todo): each `pick`-like line names the commit git resolves when the
/// operation goes on.
const TODO_FILES: &[&[u8]] = &[
    b"git-rebase-todo",
    b"git-rebase-todo.backup",
    b"done",
    b"todo",
];

/// The files of an operation directory that hold one object id: where a rebase goes `onto`,
/// the head it started from, the commit it stopped at, what an `am` or a sequencer started from.
const OID_FILES: &[&[u8]] = &[
    b"onto",
    b"orig-head",
    b"stopped-sha",
    b"amend",
    b"squash-onto",
    b"head",
    b"abort-safety",
    b"original-commit",
];

/// Todo commands whose first operand is a commit (`merge` only with `-C`/`-c`, a `fixup` may
/// carry either before it); `label`, `reset`, `update-ref`, `exec` and `break` name none.
const PICKS: &[&[u8]] = &[
    b"pick", b"p", b"reword", b"r", b"edit", b"e", b"squash", b"s", b"fixup", b"f", b"drop", b"d",
    b"revert", b"merge", b"m",
];

/// Whether `word` could be an object name git resolves: four hex digits (git's shortest
/// abbreviation, `core.abbrev=4`) up to a full sha-256 id.
fn hexish(word: &[u8]) -> bool {
    (4..=64).contains(&word.len()) && word.iter().all(u8::is_ascii_hexdigit)
}

/// Every run of hex digits in `text` that could name an object ([`hexish`]), bounded by bytes
/// that are not word bytes.
fn hex_tokens(text: &[u8], found: &mut BTreeSet<String>) {
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let mut i = 0;
    while i < text.len() {
        if !is_word(text[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < text.len() && is_word(text[i]) {
            i += 1;
        }
        let word = &text[start..i];
        if hexish(word) {
            found.insert(String::from_utf8_lossy(word).to_ascii_lowercase());
        }
    }
}

/// The commit operands of a todo list's `pick`-like lines ([`PICKS`]), as written.
fn todo_operands(text: &[u8], found: &mut Vec<Vec<u8>>) {
    for line in text.split(|b| *b == b'\n') {
        let mut words = line
            .split(u8::is_ascii_whitespace)
            .filter(|w| !w.is_empty());
        let Some(command) = words.next() else {
            continue;
        };
        if command.starts_with(b"#") || !PICKS.contains(&command) {
            continue;
        }
        let merge = command == b"merge" || command == b"m";
        let mut operand = words.next();
        if matches!(operand, Some(b"-C" | b"-c")) {
            operand = words.next();
        } else if merge {
            // A merge without `-C` names a label, not a commit.
            continue;
        }
        if let Some(word) = operand {
            found.push(word.to_vec());
        }
    }
}

/// The first word of each line of `text` (a pseudo-ref's object ids).
fn line_heads(text: &[u8], found: &mut Vec<Vec<u8>>) {
    for line in text.split(|b| *b == b'\n') {
        if let Some(word) = line.split(u8::is_ascii_whitespace).find(|w| !w.is_empty()) {
            found.push(word.to_vec());
        }
    }
}

/// How [`GitRepo::operation_objects`] reads one file of operation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Prose: its hex words are carried when they resolve.
    Text,
    /// A pending pseudo-ref: each line's first word is a dependency.
    Lines,
    /// A todo list: each `pick`-like line's commit is a dependency.
    Todo,
    /// One object id: a dependency.
    Oid,
}

/// What an operation in progress names ([`GitRepo::operation_objects`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationObjects {
    /// Every object named that git resolves to exactly one: tips of the pack.
    pub tips: Vec<String>,
    /// Dependencies of the operation git cannot resolve to exactly one object —
    /// `<file>: <name> (missing|ambiguous)`: the capture cannot know what the resumed operation
    /// needs, and a final flush over it is not complete.
    pub unresolved: Vec<String>,
}

/// Git errors.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    /// A git command failed.
    #[error("git {args}: {stderr}")]
    Command {
        /// The arguments.
        args: String,
        /// Trimmed stderr.
        stderr: String,
    },
    /// Not a git repository.
    #[error("{0} is not a git repository")]
    NotARepo(PathBuf),
    /// I/O on a path: what was done, and where.
    #[error("{op} {}: {source}", path.display())]
    IoAt {
        /// What was done (`mkdir -p`, `write`, `rename`, …).
        op: &'static str,
        /// Where.
        path: PathBuf,
        /// What the filesystem said.
        source: io::Error,
    },
    /// A git the capture would run could execute the user's code (a filter driver whose
    /// command the capture's configuration could not be shown to empty): nothing is run.
    #[error("{0}")]
    UserCode(String),
    /// I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// An I/O error on `path`, named (a bare `Permission denied` names no path).
fn at<'a>(op: &'static str, path: &'a Path) -> impl FnOnce(io::Error) -> GitError + 'a {
    move |source| GitError::IoAt {
        op,
        path: path.to_path_buf(),
        source,
    }
}

/// What [`GitRepo::set_remote`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteChange {
    /// The remote did not exist.
    Added,
    /// The remote pointed somewhere else.
    Updated,
    /// The remote already had this URL.
    Unchanged,
}

/// A repository and its directories.
#[derive(Debug, Clone)]
pub struct GitRepo {
    /// Working tree root.
    pub root: PathBuf,
    /// `git rev-parse --git-dir`, absolute.
    pub git_dir: PathBuf,
    /// `git rev-parse --git-common-dir`, absolute (differs from `git_dir` in a linked worktree).
    pub common_dir: PathBuf,
}

/// Configuration every git this module runs is given, over the repository's own, so the
/// capture reads the disk and not the user's shortcuts past it (review 2026-09-28, fourth pass,
/// #2): case-sensitive names and ignore rules (`core.ignorecase=true` left on a repository
/// moved to a case-sensitive disk made `git add` take a distinct `A` for a tracked `a`, and
/// drop it); no file-system monitor and no untracked cache (a stale answer from either leaves a
/// change unseen); every stat field compared, `ctime` included. Symlinks are symlinks
/// (`core.symlinks=false`, a setting carried from a file system without them, had `git add`
/// keep a tracked symlink's mode over the regular file that replaced it, its bytes taken for
/// the link's target, and a sealed capture restored the file as a symlink: review 2026-09-28,
/// fifth pass, #6). No hook runs (`post-index-change` fires on every index git writes), and a
/// line-end conversion git cannot reverse is converted all the same instead of failing the snap
/// (`core.safecrlf`). Passed as `GIT_CONFIG_COUNT` entries: the repository's `.git/config` is
/// never written, and a restore gets the user's configuration back byte for byte.
const CAPTURE_VIEW: [(&str, &str); 8] = [
    ("core.ignorecase", "false"),
    ("core.fsmonitor", "false"),
    ("core.untrackedCache", "false"),
    ("core.checkStat", "default"),
    ("core.trustctime", "true"),
    ("core.symlinks", "true"),
    ("core.hooksPath", "/dev/null"),
    ("core.safecrlf", "false"),
];

/// Run git with a clean environment (no inherited `GIT_DIR`/`GIT_WORK_TREE`/`GIT_INDEX_FILE`),
/// under [`CAPTURE_VIEW`], with no filter driver of the user's ([`without_filters`]). An error
/// when the filter drivers cannot be read, or cannot be shown to be off: then no git runs at
/// all, rather than one that might run the user's code (review 2026-09-28, sixth pass, #1).
///
/// Every child started from this command must be spawned through the process-wide spawn gate
/// (`sealant_process::CommandGateExt`: `output_gated`/`spawn_gated`, never `output`/`spawn`).
/// sealantd is PID 1 in the workspace and its orphan reaper reaps any waitable child it did not
/// spawn — an ungated `git` that exits mid-sweep is reaped out from under us and the `wait()`
/// here fails with `ECHILD` ("No child process"), which is how a `capture.flush` died under load.
fn git_command(cwd: &Path) -> Result<Command, GitError> {
    Ok(git_command_with(cwd, &without_filters(cwd)?))
}

/// [`git_command`] with the user's filter drivers left as they are: only for a checkout that
/// must smudge (a capture from before the raw tree, whose worktree tree holds the cleaned
/// bytes and nothing else).
fn git_command_filtering(cwd: &Path) -> Command {
    git_command_with(cwd, &[])
}

/// [`git_command`] with `extra` configuration after [`CAPTURE_VIEW`] (a later entry wins). Keys
/// and values are bytes: a filter driver's name need not be UTF-8.
fn git_command_with(cwd: &Path, extra: &[(OsString, OsString)]) -> Command {
    let mut c = Command::new("git");
    c.current_dir(cwd)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env(
            "GIT_CONFIG_COUNT",
            (CAPTURE_VIEW.len() + extra.len()).to_string(),
        )
        .stdin(Stdio::null());
    let entries = CAPTURE_VIEW
        .iter()
        .map(|(k, v)| (OsStr::new(k), OsStr::new(v)))
        .chain(extra.iter().map(|(k, v)| (k.as_os_str(), v.as_os_str())));
    for (i, (key, value)) in entries.enumerate() {
        c.env(format!("GIT_CONFIG_KEY_{i}"), key)
            .env(format!("GIT_CONFIG_VALUE_{i}"), value);
    }
    c
}

/// The variables of a filter driver that run a command (`clean`, `smudge`, `process`) or make
/// git refuse to go on without one (`required`).
const FILTER_VARS: [&[u8]; 4] = [b"clean", b"smudge", b"process", b"required"];

/// One filter driver variable as git reads it: the driver's name (bytes), the variable, and the
/// value (`None`: a key given with no `=`).
type FilterEntry = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// A filter driver variable's key: the driver's name (bytes) and the variable.
type FilterKey = (Vec<u8>, Vec<u8>);

/// `git config -z --get-regexp '^filter\.'` as `(driver, variable, value)`, in the order git
/// reads them (the last one of a key is the one git uses). The driver is the subsection's bytes
/// exactly as git has them: a subsection name may hold any byte but a newline and NUL, and one
/// that is not UTF-8 is a driver like any other (read lossily, `raw\xff` became a different
/// driver, and the user's `raw\xff` still ran). `None` for a value: a key given with no `=`.
fn filter_config(command: Command) -> Result<Vec<FilterEntry>, GitError> {
    let args = ["config", "-z", "--get-regexp", r"^filter\."];
    let mut command = command;
    let out = command.args(args).output_gated()?;
    // 1: no such key.
    if out.status.code() == Some(1) {
        return Ok(Vec::new());
    }
    let out = check(&args, out)?;
    let mut found = Vec::new();
    for record in out.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let (key, value) = match record.iter().position(|b| *b == b'\n') {
            Some(nl) => (&record[..nl], Some(record[nl + 1..].to_vec())),
            None => (record, None),
        };
        let Some(rest) = key.strip_prefix(b"filter.") else {
            continue;
        };
        // `filter.<var>` (no subsection) names no driver.
        let Some((driver, var)) = rsplit_once(rest, b".") else {
            continue;
        };
        if FILTER_VARS.contains(&var) {
            found.push((driver.to_vec(), var.to_vec(), value));
        }
    }
    Ok(found)
}

/// Configuration that empties every filter driver the configuration at `cwd` defines
/// (`clean`, `smudge` and `process` empty, `required` off), so no git a capture runs executes
/// one. A filter is the user's code, and git runs a clean filter wherever it hashes a file:
/// in `git add`, and in any command that writes an index (a racily clean entry is checked
/// against the file). One that wrote a file git had already indexed changed the disk under a
/// final flush that went on to seal it (review 2026-09-28, fifth pass, #2); one that started a
/// process left a writer running after the final flush had stopped them all and sealed (sixth
/// pass, #1). Nothing a capture runs may change the disk. A path a filter's attribute names is
/// read as it is on disk, and the raw tree holds its bytes as ever; git's own conversions (line
/// ends, `ident`, encodings) run no user code and still apply to the worktree tree.
///
/// Fails closed: the configuration cannot be read (nothing runs: the git that would have read
/// it could not have been shown to run no filter), or git, read again under the overrides,
/// still has a driver with a command or `required` on ([`GitError::UserCode`]).
fn without_filters(cwd: &Path) -> Result<Vec<(OsString, OsString)>, GitError> {
    let drivers: BTreeSet<Vec<u8>> = filter_config(git_command_filtering(cwd))?
        .into_iter()
        .map(|(driver, _, _)| driver)
        .collect();
    if drivers.is_empty() {
        return Ok(Vec::new());
    }
    let mut extra = Vec::new();
    for driver in &drivers {
        for (var, value) in [
            ("clean", ""),
            ("smudge", ""),
            ("process", ""),
            ("required", "false"),
        ] {
            let mut key = b"filter.".to_vec();
            key.extend_from_slice(driver);
            key.push(b'.');
            key.extend_from_slice(var.as_bytes());
            extra.push((OsString::from_vec(key), OsString::from(value)));
        }
    }
    // What git makes of it: the last value of every key is the one it uses.
    let mut last: BTreeMap<FilterKey, Option<Vec<u8>>> = BTreeMap::new();
    for (driver, var, value) in filter_config(git_command_with(cwd, &extra))? {
        last.insert((driver, var), value);
    }
    let left: Vec<String> = last
        .into_iter()
        .filter(
            |((_, var), value)| match (var.as_slice(), value.as_deref()) {
                (b"required", Some(v)) => !matches!(
                    v.to_ascii_lowercase().as_slice(),
                    b"false" | b"no" | b"off" | b"0" | b""
                ),
                (_, Some(v)) => !v.is_empty(),
                // A bare key: `required` on; a command variable without a value fails git itself.
                (_, None) => true,
            },
        )
        .map(|((driver, var), _)| {
            format!(
                "filter.{}.{}",
                String::from_utf8_lossy(&c_quote(&driver)),
                String::from_utf8_lossy(&var)
            )
        })
        .collect();
    if !left.is_empty() {
        return Err(GitError::UserCode(format!(
            "a filter driver of the user's is still configured under the capture's overrides: {}",
            left.join(", ")
        )));
    }
    Ok(extra)
}

fn check(args: &[&str], out: Output) -> Result<Output, GitError> {
    if out.status.success() {
        Ok(out)
    } else {
        Err(GitError::Command {
            args: args.join(" "),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        })
    }
}

fn stdout_string(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// `bytes` without its trailing line end (`\n`, `\r\n`): a ref name or target as git wrote it.
fn trim_newline(bytes: &[u8]) -> &[u8] {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    bytes.strip_suffix(b"\r").unwrap_or(bytes)
}

/// The ref a symlink at `path` names when git reads it as a symbolic ref: git stores one as a
/// symlink whose link text is the target ref's name (`core.preferSymlinkRefs`), and reads a
/// symlink under the git directory as a symbolic ref when that text is a ref name (`refs/…`,
/// well formed). `None` for anything else — not a symlink, or one git follows to the file it
/// reaches and reads that instead.
#[must_use]
pub fn symlinked_symref(path: &Path) -> Option<Vec<u8>> {
    if !fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return None;
    }
    let link = fs::read_link(path).ok()?;
    let link = link.as_os_str().as_bytes();
    (is_safe_ref_name(link) && !link.windows(2).any(|w| w == b"@{") && !link.ends_with(b"."))
        .then(|| link.to_vec())
}

/// Walk `dir` (a `refs/` directory; `name` is its ref name, `refs`) and add every loose
/// symbolic ref under it to `found`, name → target, both keys: a file reading `ref: <target>`,
/// and a symlink git reads as one ([`symlinked_symref`]; review 2026-09-28, seventh pass, #1 —
/// before, a symlink was passed over, and a symbolic ref stored as one came back direct or,
/// dangling, not at all). Any other symlink git follows, and so does this: a file it reaches
/// that reads `ref: <target>` is a symbolic ref, one it cannot reach is no ref. Lock files are
/// git's transient state, not refs.
fn collect_loose_symrefs(
    dir: &Path,
    name: &[u8],
    found: &mut BTreeMap<String, String>,
) -> Result<(), GitError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(at("list", dir)(e)),
    };
    for entry in entries {
        let entry = entry.map_err(at("list", dir))?;
        let path = entry.path();
        let file_name = entry.file_name();
        let mut child = name.to_vec();
        child.push(b'/');
        child.extend_from_slice(file_name.as_bytes());
        let kind = entry.file_type().map_err(at("stat", &path))?;
        if kind.is_dir() {
            collect_loose_symrefs(&path, &child, found)?;
            continue;
        }
        if file_name.as_bytes().ends_with(b".lock") || !(kind.is_file() || kind.is_symlink()) {
            continue;
        }
        let target = match symlinked_symref(&path) {
            Some(target) => target,
            None => {
                let bytes = match fs::read(&path) {
                    Ok(bytes) => bytes,
                    // Removed between the listing and the read: a ref that is gone.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    // A symlink git follows to nothing it can read as a ref: no ref.
                    Err(e)
                        if kind.is_symlink()
                            && (e.kind() == io::ErrorKind::IsADirectory
                                || e.kind() == io::ErrorKind::NotADirectory
                                || e.raw_os_error() == Some(nix::libc::ELOOP)) =>
                    {
                        continue;
                    }
                    Err(e) => return Err(at("read", &path)(e)),
                };
                let Some(target) = bytes.strip_prefix(b"ref: ") else {
                    continue;
                };
                trim_newline(target).to_vec()
            }
        };
        // A name git itself would ignore as broken is not a ref it holds, and one a restore
        // could not write back must not fail the restore of everything else.
        if is_safe_ref_name(&child) && is_safe_symref_target(&target) {
            found.insert(key_of(&child).into_owned(), key_of(&target).into_owned());
        } else {
            tracing::warn!(
                name = %key_of(&child),
                "capture: a loose symbolic ref git would not read is left out"
            );
        }
    }
    Ok(())
}

/// A symlink standing for `HEAD` or a loose ref ([`GitRepo::ref_symlinks`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefSymlink {
    /// The name git reads it by: `HEAD`, or `refs/…` as bytes.
    pub name: Vec<u8>,
    /// Where it is.
    pub path: PathBuf,
}

/// Add every symlink under `dir` (a `refs/` directory; `name` is its ref name) to `found`. A
/// symlink to a directory is one too; it is not descended.
fn collect_ref_symlinks(
    dir: &Path,
    name: &[u8],
    found: &mut Vec<RefSymlink>,
) -> Result<(), GitError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e)
            if e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::NotADirectory =>
        {
            return Ok(());
        }
        Err(e) => return Err(at("list", dir)(e)),
    };
    for entry in entries {
        let entry = entry.map_err(at("list", dir))?;
        let path = entry.path();
        let mut child = name.to_vec();
        child.push(b'/');
        child.extend_from_slice(entry.file_name().as_bytes());
        let kind = entry.file_type().map_err(at("stat", &path))?;
        if kind.is_dir() {
            collect_ref_symlinks(&path, &child, found)?;
        } else if kind.is_symlink() {
            found.push(RefSymlink { name: child, path });
        }
    }
    Ok(())
}

/// `path` with its `.` and `..` components taken lexically.
fn normalized(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Where the chain of symlinks starting at `path` ends, as git follows it: each link's text
/// taken from the directory it is in. The path it ends on need not exist. `None` for a chain
/// of more than 40 links (a loop) or a link that cannot be read.
#[must_use]
pub fn link_terminal(path: &Path) -> Option<PathBuf> {
    let real = |p: &Path| -> PathBuf {
        match (p.parent(), p.file_name()) {
            (Some(parent), Some(name)) => fs::canonicalize(parent)
                .map_or_else(|_| p.to_path_buf(), |parent| parent.join(name)),
            _ => p.to_path_buf(),
        }
    };
    let mut at = real(path);
    for _ in 0..40 {
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let text = fs::read_link(&at).ok()?;
                let parent = at.parent()?.to_path_buf();
                at = real(&normalized(&parent.join(text)));
            }
            _ => return Some(at),
        }
    }
    None
}

/// Where a path is, as a restore of the repository sees it ([`RefDirs::place`]).
enum Place {
    /// The loose file of this ref, in the directory git keeps it in.
    Ref(Vec<u8>),
    /// A file of the git directory the restore writes (the workspace class, `HEAD`).
    GitFile,
    /// Anywhere else.
    Elsewhere,
}

/// A repository's git directories, their real paths.
struct RefDirs {
    git_dir: Option<PathBuf>,
    common_dir: Option<PathBuf>,
}

impl RefDirs {
    fn of(repo: &GitRepo) -> Self {
        Self {
            git_dir: fs::canonicalize(&repo.git_dir).ok(),
            common_dir: fs::canonicalize(&repo.common_dir).ok(),
        }
    }

    fn place(&self, path: &Path) -> Place {
        let per_worktree = |name: &[u8]| {
            [&b"refs/bisect/"[..], b"refs/worktree/", b"refs/rewritten/"]
                .iter()
                .any(|p| name.starts_with(p))
        };
        for (dir, own) in [(&self.git_dir, true), (&self.common_dir, false)] {
            let Some(rel) = dir.as_ref().and_then(|d| path.strip_prefix(d).ok()) else {
                continue;
            };
            let rel = rel.as_os_str().as_bytes();
            if rel.starts_with(b"refs/") {
                // The file of a ref only in the directory git reads that ref from.
                let keeps = self.git_dir == self.common_dir || own == per_worktree(rel);
                if keeps && is_safe_ref_name(rel) {
                    return Place::Ref(rel.to_vec());
                }
                continue;
            }
            let first = rel.split(|b| *b == b'/').next().unwrap_or_default();
            if first != b"objects" && first != b"worktrees" && first != b"packed-refs" {
                return Place::GitFile;
            }
        }
        Place::Elsewhere
    }
}

impl GitRepo {
    /// Open the repository whose working tree is `root`.
    pub fn open(root: &Path) -> Result<Self, GitError> {
        let out = git_command(root)?
            .args(["rev-parse", "--git-dir", "--git-common-dir"])
            .output_gated()?;
        if !out.status.success() {
            return Err(GitError::NotARepo(root.to_path_buf()));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut lines = text.lines();
        let git_dir = abs(root, lines.next().unwrap_or(".git"));
        let common_dir = abs(root, lines.next().unwrap_or(".git"));
        Ok(Self {
            root: root.to_path_buf(),
            git_dir,
            common_dir,
        })
    }

    /// `git init` a repository at `root` if none exists there, then open it.
    pub fn init(root: &Path) -> Result<Self, GitError> {
        Self::init_with_format(root, "sha1")
    }

    /// `git init --object-format=<format>` a repository at `root` if none exists there, then
    /// open it; one that exists must already be of `format` (its objects cannot be read as
    /// another's), else [`GitError::Command`].
    pub fn init_with_format(root: &Path, format: &str) -> Result<Self, GitError> {
        Self::init_with_formats(root, format, "files")
    }

    /// [`Self::init_with_format`], a repository made here keeping its refs in the `ref_format`
    /// backend (`files`, `reftable`; `git init --ref-format`, asked for only when it is not
    /// `files`, so a git that predates the option makes a files repository as it always did;
    /// review 2026-09-28, ninth pass, #1). One that exists keeps its backend: the refs a
    /// restore writes through git go into whichever it is, and the workspace class then brings
    /// back the captured `.git/config` naming the backend and that backend's own files.
    pub fn init_with_formats(
        root: &Path,
        format: &str,
        ref_format: &str,
    ) -> Result<Self, GitError> {
        fs::create_dir_all(root).map_err(at("mkdir -p", root))?;
        if !root.join(".git").exists() {
            let flag = format!("--object-format={format}");
            let refs_flag = format!("--ref-format={ref_format}");
            let mut args = vec!["init", "-q", flag.as_str()];
            if ref_format != "files" {
                args.push(refs_flag.as_str());
            }
            check(&args, git_command(root)?.args(&args).output_gated()?)?;
        }
        let repo = Self::open(root)?;
        let found = repo.object_format()?;
        if found != format {
            return Err(GitError::Command {
                args: "rev-parse --show-object-format".to_owned(),
                stderr: format!(
                    "the repository at {} holds {found} objects; the capture holds {format}",
                    root.display()
                ),
            });
        }
        Ok(repo)
    }

    /// The repository's object format (`git rev-parse --show-object-format`): `sha1` or
    /// `sha256`.
    pub fn object_format(&self) -> Result<String, GitError> {
        let out = self.run(&["rev-parse", "--show-object-format"])?;
        Ok(stdout_string(&out))
    }

    /// The backend the repository keeps its refs in, as git names it: `files` or `reftable`
    /// (`git rev-parse --show-ref-format`). A git before 2.45 does not know the option (it
    /// echoes it back) and reads only the files backend; the repository then names its
    /// backend in `extensions.refStorage`, `files` when unset.
    pub fn ref_format(&self) -> Result<String, GitError> {
        let out = self.run(&["rev-parse", "--show-ref-format"])?;
        let said = stdout_string(&out);
        if !said.is_empty() && !said.starts_with('-') {
            return Ok(said);
        }
        let out = git_command(&self.root)?
            .args(["config", "--get", "extensions.refstorage"])
            .output_gated()?;
        match out.status.code() {
            Some(0) => Ok(stdout_string(&out).to_ascii_lowercase()),
            Some(1) => Ok("files".to_owned()),
            _ => Err(GitError::Command {
                args: "config --get extensions.refstorage".to_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            }),
        }
    }

    /// Add `pattern` to the repository's local excludes (`info/exclude` in the common dir) unless
    /// it is there already. The user's `.gitignore` is never touched.
    pub fn exclude_locally(&self, pattern: &str) -> Result<(), GitError> {
        let info = self.common_dir.join("info");
        fs::create_dir_all(&info).map_err(at("mkdir -p", &info))?;
        let path = info.join("exclude");
        let mut text = fs::read_to_string(&path).unwrap_or_default();
        if text.lines().any(|l| l.trim() == pattern) {
            return Ok(());
        }
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(pattern);
        text.push('\n');
        let tmp = info.join("exclude.capture-tmp");
        fs::write(&tmp, text).map_err(at("write", &tmp))?;
        fs::rename(&tmp, &path).map_err(at("rename into", &path))?;
        Ok(())
    }

    /// Whether `path` (worktree-relative) is ignored by the repository's ignore rules.
    pub fn is_ignored(&self, path: &str) -> Result<bool, GitError> {
        self.is_ignored_bytes(path.as_bytes())
    }

    /// [`Self::is_ignored`] for a path as bytes (a name that is not UTF-8).
    pub fn is_ignored_bytes(&self, path: &[u8]) -> Result<bool, GitError> {
        let out = git_command(&self.root)?
            .args(["check-ignore", "-q", "--"])
            .arg(OsStr::from_bytes(path))
            .output_gated()?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(GitError::Command {
                args: format!("check-ignore -q -- {}", key_of(path)),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            }),
        }
    }

    /// Run a git command in the working tree and return its output on success.
    pub fn run(&self, args: &[&str]) -> Result<Output, GitError> {
        check(args, git_command(&self.root)?.args(args).output_gated()?)
    }

    /// Run a git command with stdin.
    fn run_with_stdin(&self, args: &[&str], stdin: &[u8]) -> Result<Output, GitError> {
        let mut child = git_command(&self.root)?
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_gated()?;
        if let Some(mut pipe) = child.take_stdin() {
            // A closed pipe (git exited early) surfaces as the command's status.
            let _ = pipe.write_all(stdin);
        }
        check(args, child.wait_with_output()?)
    }

    /// Make `name` a remote with `url`, and say what that took. The caller validates both: they
    /// reach git as plain arguments.
    pub fn set_remote(&self, name: &str, url: &str) -> Result<RemoteChange, GitError> {
        let key = format!("remote.{name}.url");
        let current = git_command(&self.root)?
            .args(["config", "--local", "--get", &key])
            .output_gated()?;
        if !current.status.success() {
            self.run(&["remote", "add", name, url])?;
            return Ok(RemoteChange::Added);
        }
        if stdout_string(&current).trim_end_matches('\n') == url {
            return Ok(RemoteChange::Unchanged);
        }
        self.run(&["remote", "set-url", name, url])?;
        Ok(RemoteChange::Updated)
    }

    /// Ref name → sha for every ref (including `refs/stash`). A name is a [`key_of`] key of the
    /// ref's bytes, so two names that differ only in bytes that are not UTF-8 stay two refs.
    pub fn refs(&self) -> Result<BTreeMap<String, String>, GitError> {
        let out = self.run(&["for-each-ref", "--format=%(objectname) %(refname)"])?;
        // A ref name holds no control byte and no space (`git check-ref-format`): one line per
        // ref, the sha up to the first space, the name the bytes after it.
        Ok(out
            .stdout
            .split(|b| *b == b'\n')
            .filter_map(|line| {
                let space = line.iter().position(|b| *b == b' ')?;
                let (sha, name) = (&line[..space], &line[space + 1..]);
                (!name.is_empty() && !sha.is_empty()).then(|| {
                    (
                        key_of(name).into_owned(),
                        String::from_utf8_lossy(sha).into_owned(),
                    )
                })
            })
            .collect())
    }

    /// Symbolic refs other than `HEAD` (`refs/remotes/origin/HEAD` → `refs/remotes/origin/main`):
    /// ref name → the ref it points at, both [`key_of`] keys of their bytes. [`Self::refs`] lists
    /// the ones whose target resolves too, by the sha they resolve to.
    ///
    /// Read off the loose refs themselves, not `git for-each-ref`: that resolves each one and
    /// leaves out a symbolic ref whose target does not exist (a dangling
    /// `refs/remotes/origin/HEAD`), which is still a ref the repository holds. `packed-refs`
    /// cannot hold a symbolic ref, so the loose files and symlinks under `refs/` (the common
    /// directory's, and a linked worktree's own) are all of them.
    ///
    /// A reftable repository holds its symbolic refs in its tables: they are listed through
    /// git ([`Self::symrefs_in`]).
    pub fn symrefs(&self) -> Result<BTreeMap<String, String>, GitError> {
        self.symrefs_in(&self.ref_format()?)
    }

    /// [`Self::symrefs`] of a repository whose refs are in the `ref_format` backend. In a
    /// reftable repository every symbolic ref whose chain resolves is listed by `git
    /// for-each-ref` (its `%(symref)` is the end of the chain), and its immediate target is
    /// `git symbolic-ref --no-recurse`. One whose chain does not resolve is not listed by any
    /// git command: the tables, which the workspace class carries byte for byte, bring it back
    /// on a restore of every class.
    pub fn symrefs_in(&self, ref_format: &str) -> Result<BTreeMap<String, String>, GitError> {
        let mut found = BTreeMap::new();
        if ref_format != "files" {
            let out = self.run(&["for-each-ref", "--format=%(refname)%00%(symref)"])?;
            for line in out.stdout.split(|b| *b == b'\n') {
                let Some(nul) = line.iter().position(|b| *b == 0) else {
                    continue;
                };
                let (name, chain_end) = (&line[..nul], &line[nul + 1..]);
                if name.is_empty() || chain_end.is_empty() {
                    continue;
                }
                let out = git_command(&self.root)?
                    .args(["symbolic-ref", "-q", "--no-recurse", "--"])
                    .arg(OsStr::from_bytes(name))
                    .output_gated()?;
                if !out.status.success() {
                    return Err(GitError::Command {
                        args: format!("symbolic-ref --no-recurse {}", key_of(name)),
                        stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
                    });
                }
                found.insert(
                    key_of(name).into_owned(),
                    key_of(trim_newline(&out.stdout)).into_owned(),
                );
            }
            return Ok(found);
        }
        let mut dirs = vec![&self.common_dir];
        if self.git_dir != self.common_dir {
            dirs.push(&self.git_dir);
        }
        for dir in dirs {
            collect_loose_symrefs(&dir.join("refs"), b"refs", &mut found)?;
        }
        Ok(found)
    }

    /// `HEAD` as a ref name (symbolic; a [`key_of`] key of its bytes) or a sha (detached).
    ///
    /// A symbolic `HEAD` is its immediate target, read off the `HEAD` file itself: `HEAD ->
    /// refs/heads/alias -> refs/heads/main` is `refs/heads/alias` (the chain's next link is in
    /// [`Self::symrefs`]). `git symbolic-ref -q HEAD` follows the whole chain, and a restore
    /// then pointed `HEAD` at the branch the chain ended on.
    ///
    /// A reftable repository's `HEAD` file is a compatibility marker (`ref: refs/heads/.invalid`,
    /// detached or not): its `HEAD` is read through git ([`Self::head_in`]; review 2026-09-28,
    /// ninth pass, #1).
    pub fn head(&self) -> Result<String, GitError> {
        self.head_in(&self.ref_format()?)
    }

    /// [`Self::head`] of a repository whose refs are in the `ref_format` backend.
    pub fn head_in(&self, ref_format: &str) -> Result<String, GitError> {
        if ref_format != "files" {
            let out = git_command(&self.root)?
                .args(["symbolic-ref", "-q", "--no-recurse", "HEAD"])
                .output_gated()?;
            if out.status.success() {
                return Ok(key_of(trim_newline(&out.stdout)).into_owned());
            }
            let out = self.run(&["rev-parse", "--verify", "-q", "HEAD"])?;
            return Ok(stdout_string(&out));
        }
        // A `HEAD` stored as a symlink (`core.preferSymlinkRefs`) names its target in the link
        // text; reading through it would read the target's file, and skip a link of a chain.
        if let Some(target) = symlinked_symref(&self.git_dir.join("HEAD")) {
            return Ok(key_of(&target).into_owned());
        }
        if let Ok(bytes) = fs::read(self.git_dir.join("HEAD"))
            && let Some(target) = bytes.strip_prefix(b"ref: ")
        {
            let target = trim_newline(target);
            if !target.is_empty() {
                return Ok(key_of(target).into_owned());
            }
        }
        let out = git_command(&self.root)?
            .args(["symbolic-ref", "-q", "--no-recurse", "HEAD"])
            .output_gated()?;
        if out.status.success() {
            return Ok(key_of(trim_newline(&out.stdout)).into_owned());
        }
        let out = self.run(&["rev-parse", "--verify", "-q", "HEAD"]);
        match out {
            Ok(o) => Ok(stdout_string(&o)),
            Err(_) => Ok(fs::read(self.git_dir.join("HEAD"))
                .map(|bytes| {
                    let text = trim_newline(&bytes);
                    let text = text.strip_prefix(b"ref: ").unwrap_or(text);
                    key_of(text).into_owned()
                })
                .unwrap_or_else(|_| "refs/heads/main".to_owned())),
        }
    }

    /// The tree `HEAD` points at, or `None` when `HEAD` names no commit (an unborn branch).
    pub fn head_tree(&self) -> Result<Option<String>, GitError> {
        let out = git_command(&self.root)?
            .args(["rev-parse", "--verify", "-q", "HEAD^{tree}"])
            .output_gated()?;
        Ok(out.status.success().then(|| stdout_string(&out)))
    }

    /// Every sha a reflog entry points at (its old and its new value), in whichever backend
    /// the repository keeps its reflogs, every worktree's. Asked of git, never inferred from a
    /// `logs/` directory: a reftable repository has none, and its reflog-only commits were left
    /// out of a complete capture (review 2026-09-28, ninth pass, #1). The empty `--stdin` makes
    /// a repository with no reflog at all answer nothing instead of the usage text.
    pub fn reflog_tips(&self) -> Result<Vec<String>, GitError> {
        let out = self.run_with_stdin(
            &["rev-list", "--no-walk=unsorted", "--reflog", "--stdin"],
            b"",
        )?;
        Ok(stdout_string(&out).lines().map(str::to_owned).collect())
    }

    /// The objects the refs outside `refs/` name, as the repository's backend holds them:
    /// `HEAD` (resolved, detached or not) and, in a reftable repository, every root ref its
    /// tables hold (`ORIG_HEAD`, `CHERRY_PICK_HEAD`, `REBASE_HEAD`, `BISECT_EXPECTED_REV`, …:
    /// files in a files repository, which [`Self::operation_objects`] reads) — `git
    /// for-each-ref --include-root-refs` (review 2026-09-28, ninth pass, #1).
    pub fn root_ref_tips(&self, ref_format: &str) -> Result<Vec<String>, GitError> {
        if ref_format != "files" {
            let out = self.run(&[
                "for-each-ref",
                "--include-root-refs",
                "--format=%(objectname)",
            ])?;
            return Ok(stdout_string(&out)
                .lines()
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect());
        }
        let out = git_command(&self.root)?
            .args(["rev-parse", "--verify", "-q", "HEAD"])
            .output_gated()?;
        Ok(if out.status.success() {
            vec![stdout_string(&out)]
        } else {
            Vec::new()
        })
    }

    /// Every symlink of a files repository that stands for `HEAD` or a loose ref: `HEAD` in
    /// the worktree's git directory, and every symlink under `refs/` of the common directory
    /// and of the worktree's own git directory, with the name git reads it by. Whatever its
    /// link text: a symbolic ref stored as a symlink (`core.preferSymlinkRefs`), and an alias
    /// git reads through to the file it reaches (`refs/heads/alias -> main`).
    pub fn ref_symlinks(&self) -> Result<Vec<RefSymlink>, GitError> {
        let mut found = Vec::new();
        let head = self.git_dir.join("HEAD");
        if fs::symlink_metadata(&head).is_ok_and(|m| m.file_type().is_symlink()) {
            found.push(RefSymlink {
                name: b"HEAD".to_vec(),
                path: head,
            });
        }
        let mut dirs = vec![&self.common_dir];
        if self.git_dir != self.common_dir {
            dirs.push(&self.git_dir);
        }
        for dir in dirs {
            collect_ref_symlinks(&dir.join("refs"), b"refs", &mut found)?;
        }
        Ok(found)
    }

    /// The symlinks of [`Self::ref_symlinks`] that git reads as `HEAD` or a ref here and that
    /// a restore could not make resolve the same way (review 2026-09-28, ninth pass, #2). The
    /// restore writes every ref `packed-refs` and every symbolic ref loose, puts each symlink
    /// back as it was, and writes loose the ref file a symlink reaches
    /// ([`ground_ref_symlinks`]). That holds for a link whose text is a ref name (a symbolic
    /// ref), and for one whose chain ends on the file of a ref the capture holds, in the
    /// directory git keeps that ref in, or on a file of the git directory the workspace class
    /// carries. A chain that ends anywhere else — outside the repository, in the object store,
    /// on a file under `refs/` that is no ref — or that does not end, cannot come back: a final
    /// capture over it is not complete (decision 23).
    pub fn unrestorable_ref_links(
        &self,
        refs: &BTreeMap<String, String>,
        symrefs: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, GitError> {
        let dirs = RefDirs::of(self);
        let mut problems = Vec::new();
        for link in self.ref_symlinks()? {
            if symlinked_symref(&link.path).is_some() {
                continue;
            }
            let name = key_of(&link.name).into_owned();
            // A link git does not read as a ref (it reaches nothing a ref can be) is carried as
            // it is and comes back reaching the same nothing.
            if link.name != b"HEAD" && !refs.contains_key(&name) && !symrefs.contains_key(&name) {
                continue;
            }
            let fine = match link_terminal(&link.path) {
                None => false,
                Some(end) => match dirs.place(&end) {
                    Place::Ref(target) => {
                        let target = key_of(&target).into_owned();
                        refs.contains_key(&target) || symrefs.contains_key(&target)
                    }
                    Place::GitFile => true,
                    Place::Elsewhere => false,
                },
            };
            if !fine {
                problems.push(name);
            }
        }
        problems.sort();
        Ok(problems)
    }

    /// Every object a pseudo-ref or an in-progress operation's state names, which no ref or
    /// reflog may reach ([`Self::operation_objects`]'s tips).
    pub fn operation_tips(&self) -> Result<Vec<String>, GitError> {
        Ok(self.operation_objects()?.tips)
    }

    /// Every object a pseudo-ref or an in-progress operation's state names, which no ref or
    /// reflog may reach: `FETCH_HEAD` (a `git fetch <remote> <branch>` with no destination ref
    /// leaves its commit named there only), `ORIG_HEAD`, `MERGE_HEAD`, `CHERRY_PICK_HEAD`,
    /// `REVERT_HEAD`, `REBASE_HEAD`, `AUTO_MERGE`, the `BISECT_*` files, and every file of a
    /// rebase's, `am`'s or a sequencer's state directory (a todo list names commits by
    /// abbreviated id). The capture carries those files as they are; without their objects in
    /// the packs they came back naming commits no restored repository held.
    ///
    /// Read as text: every run of four to 64 hex digits (git accepts an abbreviation down to
    /// four, `core.abbrev=4`) is asked of the object store (`git cat-file --batch-check`, which
    /// resolves a name as git does), and the ones it resolves to exactly one object are tips; a
    /// word of prose that happens to look like hex only adds that object to the pack. What the
    /// operation needs to go on — each line of a pending pseudo-ref ([`PENDING_REFS`]), the
    /// commit operand of a todo list's `pick`-like lines ([`TODO_FILES`], [`PICKS`]), an
    /// operation directory's single-id files ([`OID_FILES`]) — must resolve to exactly one
    /// object, else it is [`OperationObjects::unresolved`] (review 2026-09-28, fourth pass,
    /// #3: a four-digit todo operand was not read at all, and its commit was left out of a
    /// complete capture).
    pub fn operation_objects(&self) -> Result<OperationObjects, GitError> {
        let mut words = BTreeSet::new();
        // (file, name as written) for each dependency.
        let mut needed: Vec<(String, String)> = Vec::new();
        // Documents that could not be read: what they name is unknown.
        let mut unreadable: Vec<String> = Vec::new();
        let mut read = |path: &Path, label: &str, kind: Kind| match read_document(path) {
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot read git operation state");
                unreadable.push(format!("{label}: cannot be read ({e})"));
            }
            Ok(Some(bytes)) => {
                hex_tokens(&bytes, &mut words);
                let mut found = Vec::new();
                match kind {
                    Kind::Text => {}
                    Kind::Lines => line_heads(&bytes, &mut found),
                    Kind::Todo => todo_operands(&bytes, &mut found),
                    Kind::Oid => line_heads(&bytes, &mut found),
                }
                if kind == Kind::Oid {
                    found.truncate(1);
                }
                for word in found.into_iter().filter(|w| hexish(w)) {
                    let word = String::from_utf8_lossy(&word).to_ascii_lowercase();
                    words.insert(word.clone());
                    needed.push((label.to_owned(), word));
                }
            }
        };
        let mut dirs = vec![self.git_dir.clone()];
        if self.common_dir != self.git_dir {
            dirs.push(self.common_dir.clone());
        }
        for dir in &dirs {
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                // A symlinked pseudo-ref is read as git reads it: through the link (a link
                // whose text is a ref name is that symbolic ref, whose objects the refs carry;
                // reading through it only adds them again). Skipped, its commit was left out of
                // a complete capture that kept the link (review 2026-09-28, eighth pass, #2).
                let is_file = entry
                    .file_type()
                    .is_ok_and(|t| t.is_file() || t.is_symlink());
                if is_file && names_operation_objects(name.as_bytes()) {
                    let kind = if PENDING_REFS.contains(&name.as_bytes()) {
                        Kind::Lines
                    } else {
                        Kind::Text
                    };
                    read(&entry.path(), &name.to_string_lossy(), kind);
                }
            }
            for op in OPERATION_DIRS {
                let base = dir.join(op);
                if !base.is_dir() {
                    continue;
                }
                longpath::walk(&base, &mut |visit| match visit {
                    longpath::Visit::Entry { path, kind, .. } => {
                        // A symlinked document is read through the link, as git reads it; a
                        // link to a directory is not a document.
                        let document = kind == longpath::Kind::File
                            || (kind == longpath::Kind::Symlink
                                && !fs::metadata(path).is_ok_and(|m| m.is_dir()));
                        if document {
                            let name = path.file_name().map_or(&b""[..], |n| n.as_bytes());
                            // Only the directory's own files have git's meaning.
                            let top = path.parent() == Some(base.as_path());
                            let what = if top && TODO_FILES.contains(&name) {
                                Kind::Todo
                            } else if top && OID_FILES.contains(&name) {
                                Kind::Oid
                            } else {
                                Kind::Text
                            };
                            let label = path.strip_prefix(dir).unwrap_or(path).to_string_lossy();
                            read(path, &label, what);
                        }
                        kind == longpath::Kind::Dir
                    }
                    longpath::Visit::Error { .. } => false,
                });
            }
        }
        if words.is_empty() {
            unreadable.sort();
            unreadable.dedup();
            return Ok(OperationObjects {
                tips: Vec::new(),
                unresolved: unreadable,
            });
        }
        let asked: Vec<&String> = words.iter().collect();
        let input: String = asked.iter().map(|w| format!("{w}\n")).collect();
        let out = self.run_with_stdin(&["cat-file", "--batch-check"], input.as_bytes())?;
        // One line per name asked, in order: `<oid> <type> <size>`, or `<name> missing` /
        // `<name> ambiguous`.
        let answers: Vec<&str> = std::str::from_utf8(&out.stdout)
            .unwrap_or_default()
            .lines()
            .collect();
        if answers.len() != asked.len() {
            return Err(GitError::Command {
                args: "cat-file --batch-check".to_owned(),
                stderr: format!(
                    "{} names asked, {} answers: {}",
                    asked.len(),
                    answers.len(),
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            });
        }
        let mut resolved: BTreeMap<&str, Result<&str, &str>> = BTreeMap::new();
        for (word, line) in asked.iter().zip(&answers) {
            let mut fields = line.split(' ');
            let (first, second) = (fields.next().unwrap_or(""), fields.next().unwrap_or(""));
            let object = matches!(second, "commit" | "tree" | "blob" | "tag")
                && (first.len() == 40 || first.len() == 64)
                && first.bytes().all(|b| b.is_ascii_hexdigit());
            resolved.insert(
                word.as_str(),
                if object {
                    Ok(first)
                } else if second == "ambiguous" {
                    Err("ambiguous")
                } else {
                    Err("missing")
                },
            );
        }
        let mut tips: Vec<String> = resolved
            .values()
            .filter_map(|r| r.ok().map(str::to_owned))
            .collect();
        tips.sort();
        tips.dedup();
        let mut unresolved: Vec<String> = needed
            .iter()
            .filter_map(|(file, word)| match resolved.get(word.as_str()) {
                Some(Ok(_)) => None,
                Some(Err(why)) => Some(format!("{file}: {word} ({why})")),
                None => Some(format!("{file}: {word} (missing)")),
            })
            .collect();
        unresolved.extend(unreadable);
        unresolved.sort();
        unresolved.dedup();
        Ok(OperationObjects { tips, unresolved })
    }

    /// Tree of the index, written from a scratch copy so a held `index.lock` never matters;
    /// `None` when there is no index or it has unmerged entries.
    pub fn index_tree(&self, scratch_dir: &Path) -> Result<Option<String>, GitError> {
        let real_index = self.git_dir.join("index");
        if !real_index.exists() {
            return Ok(None);
        }
        fs::create_dir_all(scratch_dir).map_err(at("mkdir -p", scratch_dir))?;
        let tmp_index = scratch_dir.join("index-tree");
        fs::copy(&real_index, &tmp_index).map_err(at("copy into", &tmp_index))?;
        let out = git_command(&self.root)?
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(["write-tree"])
            .output_gated()?;
        fs::remove_file(&tmp_index).ok();
        Ok(out.status.success().then(|| stdout_string(&out)))
    }

    /// Blobs the index references (the fallback tips when `write-tree` refuses an unmerged index).
    pub fn index_blobs(&self) -> Result<Vec<String>, GitError> {
        let out = self.run(&["ls-files", "-s"])?;
        Ok(stdout_string(&out)
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1))
            .map(str::to_owned)
            .collect())
    }

    /// `git ls-files -o --exclude-standard -z` (untranslated) against `index` when given, else
    /// the real index: the untracked paths git would add, and on stderr the directories it
    /// could not open.
    fn untracked(&self, index: Option<&Path>) -> Result<Output, GitError> {
        let mut cmd = git_command(&self.root)?;
        if let Some(index) = index {
            cmd.env("GIT_INDEX_FILE", index);
        }
        let others = ["ls-files", "-o", "--exclude-standard", "-z"];
        check(&others, cmd.env("LC_ALL", "C").args(others).output_gated()?)
    }

    /// Nested repositories under the worktree (directories holding a `.git`, the root's own
    /// excluded), relative to the root: the untracked ones git lists as a lone `dir/` entry
    /// (it never descends into an embedded repository) plus the tracked gitlinks whose
    /// directory holds a `.git` on disk. Ignored ones are not listed; they are carried by the
    /// ignored-files walk already. Read against `index` when given, else the real index.
    pub fn nested_repositories(&self, index: Option<&Path>) -> Result<Vec<String>, GitError> {
        let out = self.untracked(index)?;
        self.nested_in(&out, index)
    }

    /// [`Self::nested_repositories`] from an [`Self::untracked`] listing. Paths stay bytes
    /// until they are keys: a directory whose name is not UTF-8 is looked for on disk under its
    /// own name (decoded lossily, it was looked for under a name that does not exist, taken for
    /// no repository, and its work dropped from every class).
    fn nested_in(&self, untracked: &Output, index: Option<&Path>) -> Result<Vec<String>, GitError> {
        let holds_git = |rel: &[u8]| {
            !rel.is_empty()
                && longpath::exists(&self.root.join(OsStr::from_bytes(rel)).join(".git"))
        };
        let mut nested: Vec<String> = untracked
            .stdout
            .split(|b| *b == 0)
            .filter_map(|l| l.strip_suffix(b"/"))
            .filter(|d| holds_git(d))
            .map(|d| key_of(d).into_owned())
            .collect();
        let mut cmd = git_command(&self.root)?;
        if let Some(index) = index {
            cmd.env("GIT_INDEX_FILE", index);
        }
        let staged = ["ls-files", "-s", "-z"];
        let out = check(&staged, cmd.args(staged).output_gated()?)?;
        nested.extend(
            out.stdout
                .split(|b| *b == 0)
                .filter(|l| l.starts_with(b"160000 "))
                .filter_map(|l| l.iter().position(|b| *b == b'\t').map(|t| &l[t + 1..]))
                .filter(|p| holds_git(p))
                .map(|p| key_of(p).into_owned()),
        );
        nested.sort();
        nested.dedup();
        Ok(nested)
    }

    /// The paths of the working tree the chunked class carries for the git class: the nested
    /// repositories ([`Self::nested_repositories`]) and the paths git cannot reach
    /// ([`Self::beyond_reach`]), sorted. What a materialize sweeps and the worktree metadata
    /// overlay leaves out, as a snap decided.
    pub fn chunked_paths(&self, index: Option<&Path>) -> Result<Vec<String>, GitError> {
        let out = self.untracked(index)?;
        let mut paths = self.nested_in(&out, index)?;
        paths.extend(self.beyond_in(&out, index)?);
        paths.sort();
        paths.dedup();
        Ok(paths)
    }

    /// Untracked paths git cannot reach, relative to the root: it runs in the worktree and
    /// passes each path whole to one system call, which refuses `PATH_MAX` bytes or more (a
    /// file's path as it is; a directory's with the `/` git appends to open it,
    /// [`crate::worktree_meta::beyond_git`]). Git lists such a file, then fails the add on it
    /// (`fatal: unable to stat`); it warns that it could not open such a directory and drops
    /// it. The chunked class carries both, whatever their length. Outermost only. A path that
    /// is not UTF-8 is left to the walks that report what no class carries.
    pub fn beyond_reach(&self, index: Option<&Path>) -> Result<Vec<String>, GitError> {
        let out = self.untracked(index)?;
        self.beyond_in(&out, index)
    }

    /// [`Self::beyond_reach`] from an [`Self::untracked`] listing. Git's warning about a
    /// directory it could not open is cut at its message buffer (4 KB) exactly when the
    /// directory is too long to open, so the path is not read off it: the directory the cut
    /// text still names whole is walked (a path of any length), and every untracked,
    /// unignored directory under it that git cannot open is taken — too long, or one this
    /// walk cannot list either (the chunked class then reports it unreadable).
    fn beyond_in(&self, untracked: &Output, index: Option<&Path>) -> Result<Vec<String>, GitError> {
        let mut found: Vec<Vec<u8>> = Vec::new();
        let mut nested: Vec<&[u8]> = Vec::new();
        // (Keys go out; bytes are compared.)
        for p in untracked.stdout.split(|b| *b == 0) {
            if let Some(dir) = p.strip_suffix(b"/") {
                nested.push(dir);
            } else if crate::worktree_meta::beyond_git(p, false) {
                found.push(p.to_vec());
            }
        }
        const WARNING: &[u8] = b"warning: could not open directory '";
        let mut cut: Vec<Vec<u8>> = Vec::new();
        for line in untracked.stderr.split(|b| *b == b'\n') {
            let Some(rest) = line.strip_prefix(WARNING) else {
                continue;
            };
            if rest.windows(3).any(|w| w == b"': ") {
                // Whole: a directory git could not open for another reason, which the add
                // reports as unreadable on its own.
                continue;
            }
            let whole = rest
                .iter()
                .rposition(|b| *b == b'/')
                .map_or(&b""[..], |i| &rest[..i]);
            cut.push(whole.to_vec());
        }
        if !cut.is_empty() {
            cut.sort();
            cut.dedup();
            let mut cmd = git_command(&self.root)?;
            if let Some(index) = index {
                cmd.env("GIT_INDEX_FILE", index);
            }
            let args = [
                "ls-files",
                "-o",
                "-i",
                "--exclude-standard",
                "--directory",
                "-z",
            ];
            let ignored_out = check(&args, cmd.env("LC_ALL", "C").args(args).output_gated()?)?;
            let ignored: std::collections::BTreeSet<&[u8]> = ignored_out
                .stdout
                .split(|b| *b == 0)
                .filter(|p| !p.is_empty())
                .map(|p| p.strip_suffix(b"/").unwrap_or(p))
                .collect();
            let under_any = |rel: &[u8], set: &[&[u8]]| {
                set.iter().any(|d| {
                    rel == *d
                        || rel
                            .strip_prefix(*d)
                            .is_some_and(|r| r.first() == Some(&b'/'))
                })
            };
            let ignored_list: Vec<&[u8]> = ignored.iter().copied().collect();
            for whole in &cut {
                if cut
                    .iter()
                    .any(|o| o != whole && under_any(whole, &[o.as_slice()]))
                {
                    continue;
                }
                let base = if whole.is_empty() {
                    self.root.clone()
                } else {
                    self.root.join(std::ffi::OsStr::from_bytes(whole))
                };
                let rel_of = |path: &Path| -> Vec<u8> {
                    path.strip_prefix(&self.root)
                        .unwrap_or(path)
                        .as_os_str()
                        .as_bytes()
                        .to_vec()
                };
                longpath::walk(&base, &mut |visit| {
                    let (path, kind) = match visit {
                        longpath::Visit::Entry { path, kind, .. } => (path, kind),
                        longpath::Visit::Error { path, error, .. } => {
                            if !crate::index::is_vanished(&error) {
                                found.push(rel_of(path));
                            }
                            return false;
                        }
                    };
                    let rel = rel_of(path);
                    if under_any(&rel, &ignored_list) || under_any(&rel, &nested) {
                        return false;
                    }
                    if kind != longpath::Kind::Dir {
                        if crate::worktree_meta::beyond_git(&rel, false) {
                            found.push(rel);
                        }
                        return false;
                    }
                    if path.file_name() == Some(std::ffi::OsStr::new(".git")) {
                        return false;
                    }
                    if crate::worktree_meta::beyond_git(&rel, true) {
                        found.push(rel);
                        return false;
                    }
                    true
                });
            }
        }
        // Keys of the bytes: a name that is not UTF-8 is carried like any other (it was left out,
        // for a walk that only reported it).
        found.sort();
        found.dedup();
        let outer: Vec<String> = found
            .iter()
            .filter(|p| !found.iter().any(|o| o != *p && at_or_under(p, o)))
            .map(|p| key_of(p).into_owned())
            .collect();
        Ok(outer)
    }

    /// The `git add` flags and pathspecs for [`Self::worktree_tree`], the nested repositories
    /// it leaves out and the paths git cannot reach ([`Self::beyond_reach`]). `excludes`,
    /// every nested repository under the root and every path beyond git's reach become
    /// `:(exclude)` pathspec items, so `add -A` never reaches a path git cannot index: a nested
    /// repository with no commit checked out is a fatal error on git 2.52 (`--ignore-errors`
    /// does not cover "does not have a commit checked out" there) and a skipped "unable to
    /// index" error on 2.55; one with a commit would become an embedded gitlink that carries
    /// none of its bytes; a file too long for one system call is fatal ("unable to stat"). The
    /// chunked class carries the bytes in every case, so all are excluded alike and returned.
    /// An exclude git already ignores (the local exclude the engine adds at boot) is skipped by
    /// `.` on its own; naming it in a pathspec makes `git add` report it as an ignored path and
    /// exit 1, so only the paths git would otherwise index get a pathspec item. Nested
    /// repositories below an exclude are left out of the returned list: they are not part of
    /// the tree the worktree tree describes. The pathspecs travel in a file
    /// (`--pathspec-from-file`): a thousand paths of 4 KB would not fit an argument list.
    fn worktree_add_args(
        &self,
        tmp_index: &Path,
        excludes: &[String],
    ) -> Result<AddArgs, GitError> {
        // `--ignore-errors` stays as belt and braces for anything the enumeration missed.
        let args: Vec<String> = ["add", "-A", "--ignore-errors"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let mut pathspecs: Vec<Vec<u8>> = vec![b".".to_vec()];
        let excludes: Vec<&[u8]> = excludes
            .iter()
            .map(|e| e.trim_matches('/').as_bytes())
            .filter(|e| !e.is_empty())
            .collect();
        for e in &excludes {
            if !self.is_ignored_bytes(e)? {
                pathspecs.push(exclude_spec(e));
            }
        }
        let under_exclude = |p: &[u8]| excludes.iter().any(|e| at_or_under(p, e));
        let untracked = self.untracked(Some(tmp_index))?;
        let mut nested = Vec::new();
        for n in self.nested_in(&untracked, Some(tmp_index))? {
            let bytes = bytes_of(&n).into_owned();
            if under_exclude(&bytes) {
                continue;
            }
            if !self.is_ignored_bytes(&bytes)? {
                pathspecs.push(exclude_spec(&bytes));
            }
            nested.push(n);
        }
        let mut beyond = Vec::new();
        for b in self.beyond_in(&untracked, Some(tmp_index))? {
            let bytes = bytes_of(&b).into_owned();
            if under_exclude(&bytes) || nested.iter().any(|n| at_or_under(&bytes, &bytes_of(n))) {
                continue;
            }
            pathspecs.push(exclude_spec(&bytes));
            beyond.push(b);
        }
        Ok(AddArgs {
            args,
            pathspecs,
            nested,
            beyond,
        })
    }

    /// Take the user's shortcuts past the disk out of `index` (a scratch copy of the user's
    /// index; the real one is never touched): `assume-unchanged` from every entry, and
    /// `skip-worktree` from every entry whose path is on disk. With either bit git never looks
    /// at the file, so an edit behind it kept the index's blob, and a complete final flush
    /// restored the old bytes (review 2026-09-28, fourth pass, #2). An entry the sparse checkout
    /// keeps off the disk keeps its bit: it is not there to read, and `add -A` would take it
    /// for a deletion. The restored index is the user's own, bits and all.
    fn clear_index_shortcuts(&self, index: &Path) -> Result<(), GitError> {
        let ls = ["ls-files", "-v", "-z"];
        let listed = check(
            &ls,
            git_command(&self.root)?
                .env("GIT_INDEX_FILE", index)
                .args(ls)
                .output_gated()?,
        )?;
        let mut assumed: Vec<u8> = Vec::new();
        let mut skipped: Vec<u8> = Vec::new();
        for record in listed.stdout.split(|b| *b == 0) {
            let (Some(&tag), Some(b' ')) = (record.first(), record.get(1)) else {
                continue;
            };
            let path = &record[2..];
            // `ls-files -v` tags an assume-unchanged entry in lower case; `S`/`s` is
            // skip-worktree.
            if tag.is_ascii_lowercase() {
                assumed.extend_from_slice(path);
                assumed.push(0);
            }
            if matches!(tag, b'S' | b's')
                && longpath::symlink_metadata(&self.root.join(OsStr::from_bytes(path))).is_ok()
            {
                skipped.extend_from_slice(path);
                skipped.push(0);
            }
        }
        for (flag, paths) in [
            ("--no-assume-unchanged", assumed),
            ("--no-skip-worktree", skipped),
        ] {
            if paths.is_empty() {
                continue;
            }
            let args = ["update-index", flag, "-z", "--stdin"];
            let mut child = git_command(&self.root)?
                .env("GIT_INDEX_FILE", index)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn_gated()?;
            let writer = child.take_stdin().map(|mut pipe| {
                std::thread::spawn(move || {
                    let _ = pipe.write_all(&paths);
                })
            });
            let out = child.wait_with_output()?;
            if let Some(writer) = writer {
                let _ = writer.join();
            }
            check(&args, out)?;
        }
        Ok(())
    }

    /// Run `git add` as [`AddArgs`] says against `tmp_index`, its pathspecs from a file beside
    /// it, untranslated (what could not be read is read off the messages).
    fn run_add(&self, tmp_index: &Path, add: &AddArgs) -> Result<Output, GitError> {
        let mut command = git_command(&self.root)?;
        let spec_file = tmp_index.with_extension("pathspecs");
        let mut specs: Vec<u8> = Vec::new();
        for p in &add.pathspecs {
            specs.extend_from_slice(p);
            specs.push(0);
        }
        fs::write(&spec_file, &specs).map_err(at("write", &spec_file))?;
        let out = command
            .env("GIT_INDEX_FILE", tmp_index)
            .env("LC_ALL", "C")
            .args(&add.args)
            .arg(format!("--pathspec-from-file={}", spec_file.display()))
            .arg("--pathspec-file-nul")
            .output_gated();
        fs::remove_file(&spec_file).ok();
        Ok(out?)
    }

    /// Tree of the working tree: a throwaway copy of the index with `git add -A` applied, then
    /// `write-tree`. Nested repositories are left out of the add (see
    /// [`Self::worktree_add_args`]) and their paths are returned beside the sha so the chunked
    /// class can carry them; a tracked gitlink keeps the entry the index already had.
    ///
    /// Tracked always wins: a path the index holds is part of the tree whatever the ignore rules
    /// say (`git add -A` only consults them for untracked paths). Without an index on disk the
    /// throwaway one is seeded from `HEAD`'s tree, so the tracked files of the checked-out
    /// commit keep that standing — from an empty index, a tracked file that happens to match
    /// `.gitignore` (`core.*` against a tracked `core.json`) would be taken for an ignored one
    /// and dropped from the tree.
    pub fn worktree_tree(
        &self,
        scratch_dir: &Path,
        excludes: &[String],
    ) -> Result<(String, Vec<String>), GitError> {
        let wt = self.worktree_tree_carrying(scratch_dir, excludes, None)?;
        Ok((wt.tree, wt.gitlinks))
    }

    /// [`Self::worktree_tree`], and what `git add` could not read: a directory it could not
    /// open (it skips one with a warning, so an untracked one would silently drop out of the
    /// tree and a tracked one fall back to the index's stale blobs) or a path it could not
    /// stat or open. With `carry_from` (the previous capture's worktree tree), each such path
    /// takes that tree's entry, never a deletion; see [`WorktreeTree`].
    pub fn worktree_tree_carrying(
        &self,
        scratch_dir: &Path,
        excludes: &[String],
        carry_from: Option<&str>,
    ) -> Result<WorktreeTree, GitError> {
        self.worktree_tree_with(
            scratch_dir,
            excludes,
            TreeOptions {
                carry_from,
                ..TreeOptions::default()
            },
        )
    }

    /// [`Self::worktree_tree_carrying`] as `options` say, and the raw tree beside it
    /// ([`WorktreeTree::raw_tree`]).
    pub fn worktree_tree_with(
        &self,
        scratch_dir: &Path,
        excludes: &[String],
        options: TreeOptions<'_>,
    ) -> Result<WorktreeTree, GitError> {
        fs::create_dir_all(scratch_dir).map_err(at("mkdir -p", scratch_dir))?;
        let tmp_index = scratch_dir.join("snap-index");
        let real_index = self.git_dir.join("index");
        let seed = |tmp_index: &Path| -> Result<(), GitError> {
            fs::remove_file(tmp_index).ok();
            if let Ok(real) = fs::metadata(&real_index) {
                fs::copy(&real_index, tmp_index).map_err(at("copy into", tmp_index))?;
                self.clear_index_shortcuts(tmp_index)?;
                // Git trusts an entry's stat data only when the index was written after the file
                // changed (an entry as new as the index is "racily clean" and re-read): the copy
                // keeps the real index's mtime, so it is exactly as trusting as the user's own.
                let mtime = real.mtime().saturating_mul(1_000_000_000) + real.mtime_nsec();
                longpath::set_mtime_nofollow(tmp_index, mtime)
                    .map_err(at("set the mtime of", tmp_index))?;
            } else if let Some(head_tree) = self.head_tree()? {
                let rt = ["read-tree", &head_tree];
                check(
                    &rt,
                    git_command(&self.root)?
                        .env("GIT_INDEX_FILE", tmp_index)
                        .args(rt)
                        .output_gated()?,
                )?;
            }
            Ok(())
        };
        seed(&tmp_index)?;
        let mut add = self.worktree_add_args(&tmp_index, excludes)?;
        // A path git dies on (`fatal: unable to stat '<p>'`: a file it listed and cannot stat)
        // fails that path only: it joins the chunked class, which reads it or reports it
        // unreadable, and the add runs again without it. Bounded; each round names a new path.
        let mut out = self.run_add(&tmp_index, &add)?;
        for _ in 0..FATAL_PATH_RETRIES {
            if out.status.success() {
                break;
            }
            let fatal: Vec<String> = out
                .stderr
                .split(|b| *b == b'\n')
                .filter_map(|l| l.strip_prefix(b"fatal: unable to stat '"))
                .filter_map(|l| rsplit_once(l, b"': ").map(|(p, _)| key_of(p).into_owned()))
                .filter(|p| !p.is_empty() && !add.beyond.contains(p))
                .collect();
            if fatal.is_empty() {
                break;
            }
            for p in fatal {
                tracing::warn!(path = %p, "git cannot stat this path; the chunked class carries it");
                add.pathspecs.push(exclude_spec(&bytes_of(&p)));
                add.beyond.push(p);
            }
            // The add died part way: start again from the index it was given.
            seed(&tmp_index)?;
            out = self.run_add(&tmp_index, &add)?;
        }
        let AddArgs {
            args,
            pathspecs,
            mut nested,
            mut beyond,
        } = add;
        // Belt and braces: anything `--ignore-errors` skipped past that the enumeration did not
        // name joins the chunked class the same way.
        let mut unindexed: Vec<String> = out
            .stderr
            .split(|b| *b == b'\n')
            .filter_map(|l| l.strip_prefix(b"error: unable to index file '"))
            .filter_map(|l| l.strip_suffix(b"'"))
            .map(|p| key_of(p.strip_suffix(b"/").unwrap_or(p)).into_owned())
            .collect();
        if !out.status.success() && unindexed.is_empty() {
            return Err(GitError::Command {
                args: format!(
                    "{} -- {}",
                    args.join(" "),
                    pathspecs
                        .iter()
                        .map(|p| key_of(p).into_owned())
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            });
        }
        let unreadable = unreadable_in_add(&self.root, &out.stderr);
        let carried = match options.carry_from {
            Some(from) => self.carry_into_index(&tmp_index, from, &unreadable),
            None => Vec::new(),
        };
        let tree = self.write_tree(&tmp_index)?;
        let ls = ["ls-files", "-s", "-z"];
        let listed = check(
            &ls,
            git_command(&self.root)?
                .env("GIT_INDEX_FILE", &tmp_index)
                .args(ls)
                .output_gated()?,
        )?;
        let entries = index_entries(&listed.stdout);
        let mut gitlinks: Vec<String> = entries
            .iter()
            .filter(|e| e.mode == "160000")
            .map(|e| key_of(&e.path).into_owned())
            .collect();
        gitlinks.append(&mut unindexed);
        gitlinks.append(&mut nested);
        gitlinks.append(&mut beyond);
        gitlinks.sort();
        gitlinks.dedup();
        let raw_tree = self.raw_tree(&tmp_index, &tree, &entries, &unreadable, options)?;
        fs::remove_file(&tmp_index).ok();
        Ok(WorktreeTree {
            tree,
            raw_tree,
            gitlinks,
            unreadable,
            carried,
        })
    }

    /// `git write-tree` of `index`.
    fn write_tree(&self, index: &Path) -> Result<String, GitError> {
        let wt = ["write-tree"];
        let out = check(
            &wt,
            git_command(&self.root)?
                .env("GIT_INDEX_FILE", index)
                .args(wt)
                .output_gated()?,
        )?;
        Ok(stdout_string(&out))
    }

    /// The raw tree of `tree` (written from `tmp_index`, whose entries are `entries`): every
    /// regular file takes a blob of its bytes as they are on disk (`git hash-object
    /// --no-filters`), whatever git's attributes or `core.autocrlf` did to it on its way into the
    /// tree (a clean filter, `text`/`eol`/`crlf` line-end normalization,
    /// `working-tree-encoding`, `ident`); a file whose bytes are the tree's blob keeps its entry.
    /// `tree` itself when nothing differs. Every file, not only the ones some attribute file is
    /// seen to name: git reads a `.gitattributes` the index does not hold (an ignored one
    /// included), and a raw tree that asked only when it found one among the index entries took
    /// the cleaned blob for a CRLF file and a sealed restore wrote LF (review 2026-09-28, sixth
    /// pass, #7). The blob ids are cached by stat ([`TreeOptions::raw_cache`]), so a file is
    /// read again only once its stat moved.
    /// The index `git add` wrote and the user's real index are not touched: the raw blobs go
    /// into a copy. A path in `unreadable` takes the entry `options.carry_raw_from` (the previous
    /// raw tree) holds for it, else keeps `tree`'s. A file that cannot be read raw here (gone
    /// since the add) keeps `tree`'s entry; the next snap reads it again.
    fn raw_tree(
        &self,
        tmp_index: &Path,
        tree: &str,
        entries: &[IndexEntry],
        unreadable: &[(String, String)],
        options: TreeOptions<'_>,
    ) -> Result<String, GitError> {
        let skip: BTreeSet<Vec<u8>> = unreadable
            .iter()
            .map(|(p, _)| bytes_of(p).into_owned())
            .collect();
        let files: Vec<&IndexEntry> = entries
            .iter()
            .filter(|e| e.stage == "0" && (e.mode == "100644" || e.mode == "100755"))
            .filter(|e| !skip.iter().any(|s| at_or_under(&e.path, s)))
            .collect();
        let candidates = files;
        let carry_raw = options.carry_raw_from.filter(|_| !unreadable.is_empty());
        if candidates.is_empty() && carry_raw.is_none() {
            return Ok(tree.to_owned());
        }
        let mut cache = RawCache::load(options.raw_cache);
        let mut shas: Vec<Option<String>> = vec![None; candidates.len()];
        let mut stats: Vec<Option<fs::Metadata>> = Vec::with_capacity(candidates.len());
        let mut to_hash: Vec<usize> = Vec::new();
        for (i, e) in candidates.iter().enumerate() {
            let meta = longpath::symlink_metadata(&self.root.join(OsStr::from_bytes(&e.path)))
                .ok()
                .filter(fs::Metadata::is_file);
            match meta.as_ref().and_then(|m| cache.hit(&e.path, m)) {
                Some(sha) => shas[i] = Some(sha),
                None if meta.is_some() => to_hash.push(i),
                None => {}
            }
            stats.push(meta);
        }
        // A cached blob pruned from the object store since is hashed again.
        let cached: Vec<String> = shas.iter().flatten().cloned().collect();
        if !cached.is_empty() {
            let present: BTreeSet<String> = self.existing(&cached)?.into_iter().collect();
            for (i, sha) in shas.iter_mut().enumerate() {
                if sha.as_ref().is_some_and(|s| !present.contains(s)) {
                    *sha = None;
                    to_hash.push(i);
                }
            }
        }
        let paths: Vec<&[u8]> = to_hash
            .iter()
            .map(|i| candidates[*i].path.as_slice())
            .collect();
        for (i, sha) in to_hash.iter().zip(self.hash_raw(&paths)?) {
            if let (Some(sha), Some(meta)) = (&sha, &stats[*i]) {
                cache.record(&candidates[*i].path, meta, sha);
            }
            shas[*i] = sha;
        }
        cache.retain_only(candidates.iter().map(|e| e.path.as_slice()));
        cache.save(options.raw_cache);
        let changed: Vec<(&IndexEntry, String)> = candidates
            .iter()
            .zip(shas)
            .filter_map(|(e, sha)| sha.filter(|s| *s != e.sha).map(|s| (*e, s)))
            .collect();
        if changed.is_empty() && carry_raw.is_none() {
            return Ok(tree.to_owned());
        }
        let raw_index = tmp_index.with_file_name("snap-index-raw");
        fs::remove_file(&raw_index).ok();
        fs::copy(tmp_index, &raw_index).map_err(at("copy into", &raw_index))?;
        let result = (|| {
            if let Some(from) = carry_raw {
                self.carry_into_index(&raw_index, from, unreadable);
            }
            if !changed.is_empty() {
                let mut info: Vec<u8> = Vec::new();
                for (e, sha) in &changed {
                    info.extend_from_slice(e.mode.as_bytes());
                    info.push(b' ');
                    info.extend_from_slice(sha.as_bytes());
                    info.push(b'\t');
                    info.extend_from_slice(&e.path);
                    info.push(0);
                }
                let args = ["update-index", "-z", "--index-info"];
                let mut child = git_command(&self.root)?
                    .env("GIT_INDEX_FILE", &raw_index)
                    .args(args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn_gated()?;
                if let Some(mut pipe) = child.take_stdin() {
                    let _ = pipe.write_all(&info);
                }
                check(&args, child.wait_with_output()?)?;
            }
            self.write_tree(&raw_index)
        })();
        fs::remove_file(&raw_index).ok();
        result
    }

    /// Whether `core.autocrlf` (any config level) converts line ends on the way into the tree
    /// for a file no attribute speaks of: `true` or `input`.
    fn autocrlf_active(&self) -> Result<bool, GitError> {
        let out = git_command(&self.root)?
            .args(["config", "--get", "core.autocrlf"])
            .output_gated()?;
        let value = stdout_string(&out).to_ascii_lowercase();
        Ok(out.status.success() && !matches!(value.as_str(), "" | "false" | "no" | "off" | "0"))
    }

    /// `git check-attr -z --stdin` of the attributes that convert, for the NUL-separated
    /// `paths`, against `index` when given.
    fn attrs_of(&self, index: Option<&Path>, paths: &[u8]) -> Result<Vec<u8>, GitError> {
        let args = [
            "check-attr",
            "-z",
            "--stdin",
            "text",
            "eol",
            "crlf",
            "filter",
            "working-tree-encoding",
            "ident",
        ];
        let mut cmd = git_command(&self.root)?;
        if let Some(index) = index {
            cmd.env("GIT_INDEX_FILE", index);
        }
        let mut child = cmd
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_gated()?;
        // Written from another thread: the answer for a long list fills the pipe before the
        // question is all asked.
        let writer = child.take_stdin().map(|mut pipe| {
            let paths = paths.to_vec();
            std::thread::spawn(move || {
                let _ = pipe.write_all(&paths);
            })
        });
        let out = child.wait_with_output()?;
        if let Some(writer) = writer {
            let _ = writer.join();
        }
        Ok(check(&args, out)?.stdout)
    }

    /// Blobs of `paths` (root-relative) as their bytes are on disk, written into the object
    /// store with no filter or conversion (`git hash-object -w --no-filters`); `None` for a
    /// path that could not be read.
    fn hash_raw(&self, paths: &[&[u8]]) -> Result<Vec<Option<String>>, GitError> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let mut input: Vec<u8> = Vec::new();
        for p in paths {
            input.extend_from_slice(&c_quote(p));
            input.push(b'\n');
        }
        let args = ["hash-object", "-w", "--no-filters", "--stdin-paths"];
        let mut child = git_command(&self.root)?
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_gated()?;
        let writer = child.take_stdin().map(|mut pipe| {
            std::thread::spawn(move || {
                let _ = pipe.write_all(&input);
            })
        });
        let out = child.wait_with_output()?;
        if let Some(writer) = writer {
            let _ = writer.join();
        }
        let shas: Vec<String> = stdout_string(&out).lines().map(str::to_owned).collect();
        if out.status.success() && shas.len() == paths.len() {
            return Ok(shas.into_iter().map(Some).collect());
        }
        // One path it could not read ends the batch: each path alone, then.
        let mut each = Vec::with_capacity(paths.len());
        for p in paths {
            let out = git_command(&self.root)?
                .args(["hash-object", "-w", "--no-filters", "--"])
                .arg(OsStr::from_bytes(p))
                .output_gated()?;
            each.push(out.status.success().then(|| stdout_string(&out)));
        }
        Ok(each)
    }

    /// Give each unreadable path in `tmp_index` the entry `from` (a tree) holds for it: the
    /// index's entries at and under the path are removed, then a subtree is read in under the
    /// path's prefix, or a blob (or gitlink) entry is added. A path `from` does not hold is left
    /// as `git add` left it (an untracked one absent, a tracked one at the index's blob).
    /// Returns the paths carried (keys); a git failure skips that path, logged.
    fn carry_into_index(
        &self,
        tmp_index: &Path,
        from: &str,
        unreadable: &[(String, String)],
    ) -> Vec<String> {
        let git = |args: &[&OsStr]| -> Result<Output, GitError> {
            let out = git_command(&self.root)?
                .env("GIT_INDEX_FILE", tmp_index)
                .env("GIT_LITERAL_PATHSPECS", "1")
                .args(args)
                .output_gated()?;
            if out.status.success() {
                Ok(out)
            } else {
                Err(GitError::Command {
                    args: args
                        .iter()
                        .map(|a| key_of(a.as_bytes()).into_owned())
                        .collect::<Vec<_>>()
                        .join(" "),
                    stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
                })
            }
        };
        let os = OsStr::new;
        let mut carried = Vec::new();
        for (path, _) in unreadable {
            let bytes = bytes_of(path);
            let raw = OsStr::from_bytes(&bytes);
            let carry = || -> Result<bool, GitError> {
                let listed = git(&[os("ls-tree"), os("-z"), os(from), os("--"), raw])?;
                let Some(record) = listed.stdout.split(|b| *b == 0).next() else {
                    return Ok(false);
                };
                let Some(tab) = record.iter().position(|b| *b == b'\t') else {
                    return Ok(false);
                };
                let meta = String::from_utf8_lossy(&record[..tab]).into_owned();
                let mut fields = meta.split(' ');
                let (Some(mode), Some(kind), Some(sha)) =
                    (fields.next(), fields.next(), fields.next())
                else {
                    return Ok(false);
                };
                git(&[
                    os("rm"),
                    os("-r"),
                    os("--cached"),
                    os("-f"),
                    os("-q"),
                    os("--ignore-unmatch"),
                    os("--"),
                    raw,
                ])?;
                if kind == "tree" {
                    let mut prefix = OsString::from("--prefix=");
                    prefix.push(raw);
                    prefix.push("/");
                    git(&[os("read-tree"), &prefix, os(sha)])?;
                } else {
                    let mut info = OsString::from(format!("{mode},{sha},"));
                    info.push(raw);
                    git(&[os("update-index"), os("--add"), os("--cacheinfo"), &info])?;
                }
                Ok(true)
            };
            match carry() {
                Ok(true) => carried.push(path.clone()),
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%path, %error, "could not carry an unreadable path from the previous capture");
                }
            }
        }
        carried
    }

    /// Filter `shas` to the ones the object store holds.
    pub fn existing(&self, shas: &[String]) -> Result<Vec<String>, GitError> {
        if shas.is_empty() {
            return Ok(Vec::new());
        }
        let input = shas.iter().map(|s| format!("{s}\n")).collect::<String>();
        let out = self.run_with_stdin(&["cat-file", "--batch-check"], input.as_bytes())?;
        Ok(stdout_string(&out)
            .lines()
            .filter(|l| !l.ends_with(" missing"))
            .filter_map(|l| l.split_whitespace().next())
            .map(str::to_owned)
            .collect())
    }

    /// `git fsck --connectivity-only --no-dangling`.
    pub fn fsck(&self) -> Result<FsckStatus, GitError> {
        let out = git_command(&self.root)?
            .args(["fsck", "--connectivity-only", "--no-dangling"])
            .output_gated()?;
        Ok(if out.status.success() {
            FsckStatus::Verified
        } else {
            FsckStatus::Failed
        })
    }

    /// `git status --porcelain`.
    pub fn status_porcelain(&self) -> Result<String, GitError> {
        Ok(stdout_string(&self.run(&["status", "--porcelain"])?))
    }
}

fn abs(root: &Path, p: &str) -> PathBuf {
    let path = Path::new(p);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

/// A worktree tree and what went into it ([`GitRepo::worktree_tree_carrying`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeTree {
    /// The tree, as `git add -A` stages the working tree (attributes and filters applied).
    pub tree: String,
    /// `tree` with every regular file git's attributes or `core.autocrlf` may convert holding
    /// its bytes as they are on disk; `tree` itself when no file differs.
    pub raw_tree: String,
    /// Nested repositories and paths git could not index (the chunked class carries them).
    pub gitlinks: Vec<String>,
    /// Paths `git add` could not read, root-relative, with what the filesystem said: each one
    /// verified on disk (it exists and cannot be listed, stat'ed or opened), outermost only.
    pub unreadable: Vec<(String, String)>,
    /// Of `unreadable`, the paths that took the previous capture's entry.
    pub carried: Vec<String>,
}

/// The paths `git add` (run with `LC_ALL=C`) said it could not read: `warning: could not open
/// directory '<p>/': …`, `error: open("<p>"): …`, and a bare `<p>: …` (a tracked path it could
/// not stat). A candidate counts only when the filesystem agrees it exists and cannot be read;
/// a path under another kept one is dropped. Paths are read as bytes and returned as keys: a
/// name that is not UTF-8 is checked on disk under its own name.
fn unreadable_in_add(root: &Path, stderr: &[u8]) -> Vec<(String, String)> {
    let mut found: Vec<(Vec<u8>, String)> = Vec::new();
    for line in stderr.split(|b| *b == b'\n') {
        let candidate =
            if let Some(rest) = line.strip_prefix(b"warning: could not open directory '") {
                rsplit_once(rest, b"': ").map(|(p, _)| p)
            } else if let Some(rest) = line.strip_prefix(b"error: open(\"") {
                rsplit_once(rest, b"\"): ").map(|(p, _)| p)
            } else if line.starts_with(b"error: ")
                || line.starts_with(b"warning: ")
                || line.starts_with(b"fatal: ")
            {
                None
            } else {
                rsplit_once(line, b": ").map(|(p, _)| p)
            };
        let Some(p) = candidate.map(|p| p.strip_suffix(b"/").unwrap_or(p)) else {
            continue;
        };
        if p.is_empty() || p.first() == Some(&b'/') || found.iter().any(|(f, _)| f == p) {
            continue;
        }
        let abs = root.join(OsStr::from_bytes(p));
        let error = match longpath::symlink_metadata(&abs) {
            Err(e) => Some(e),
            Ok(m) if m.is_dir() => longpath::read_dir(&abs).err(),
            Ok(m) if m.is_file() => longpath::open(&abs).err(),
            Ok(_) => None,
        };
        if let Some(e) = error
            && !crate::index::is_vanished(&e)
        {
            found.push((p.to_vec(), e.to_string()));
        }
    }
    found.sort();
    found
        .iter()
        .filter(|(p, _)| !found.iter().any(|(o, _)| o != p && at_or_under(p, o)))
        .map(|(p, e)| (key_of(p).into_owned(), e.clone()))
        .collect()
}

/// `bytes` split at the last `sep`.
fn rsplit_once<'b>(bytes: &'b [u8], sep: &[u8]) -> Option<(&'b [u8], &'b [u8])> {
    let at = bytes.windows(sep.len()).rposition(|w| w == sep)?;
    Some((&bytes[..at], &bytes[at + sep.len()..]))
}

/// One `git ls-files -s -z` record.
#[derive(Debug, Clone)]
struct IndexEntry {
    mode: String,
    sha: String,
    stage: String,
    path: Vec<u8>,
}

fn index_entries(listing: &[u8]) -> Vec<IndexEntry> {
    listing
        .split(|b| *b == 0)
        .filter_map(|record| {
            let tab = record.iter().position(|b| *b == b'\t')?;
            let head = String::from_utf8_lossy(&record[..tab]).into_owned();
            let mut fields = head.split(' ');
            Some(IndexEntry {
                mode: fields.next()?.to_owned(),
                sha: fields.next()?.to_owned(),
                stage: fields.next()?.to_owned(),
                path: record[tab + 1..].to_vec(),
            })
        })
        .collect()
}

/// Whether a `git check-attr` answer means the path's bytes are converted between the working
/// tree and the object store.
fn converts(attr: &[u8], value: &[u8]) -> bool {
    match attr {
        b"text" | b"crlf" | b"filter" | b"working-tree-encoding" => {
            value != b"unspecified" && value != b"unset"
        }
        b"eol" => value != b"unspecified",
        b"ident" => value == b"set",
        _ => false,
    }
}

/// `path` quoted the way git unquotes a path read from `--stdin-paths` (C style): every byte
/// that is not printable ASCII as an octal escape, `"` and `\` escaped.
fn c_quote(path: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len() + 2);
    out.push(b'"');
    for b in path {
        match *b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x20..=0x7e => out.push(*b),
            other => out.extend_from_slice(format!("\\{other:03o}").as_bytes()),
        }
    }
    out.push(b'"');
    out
}

/// What a worktree tree build carries over from the previous capture, and where it keeps the
/// raw-blob cache ([`GitRepo::worktree_tree_with`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct TreeOptions<'a> {
    /// The previous capture's worktree tree: an unreadable path takes its entry.
    pub carry_from: Option<&'a str>,
    /// The previous capture's raw tree: an unreadable path takes its entry in the raw tree.
    pub carry_raw_from: Option<&'a str>,
    /// Where the raw tree's blob ids are remembered by file stat, so a file whose stat has not
    /// moved is not read again (none: every regular file is read each time).
    pub raw_cache: Option<&'a Path>,
}

/// A file's stat as the raw-blob cache keys it, and the blob of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RawEntry {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    sha: String,
}

impl RawEntry {
    fn stat_of(meta: &fs::Metadata) -> (u64, u64, u64, (i64, i64), (i64, i64)) {
        (
            meta.dev(),
            meta.ino(),
            meta.len(),
            (meta.mtime(), meta.mtime_nsec()),
            (meta.ctime(), meta.ctime_nsec()),
        )
    }
}

/// The raw tree's blob ids by path (keys) and stat ([`TreeOptions::raw_cache`]). A file changed
/// within [`RAW_CACHE_RACY_SECS`] of being read is not remembered: a write in the same
/// timestamp tick would leave its stat as it was.
#[derive(Debug, Default, Serialize, Deserialize)]
struct RawCache {
    entries: BTreeMap<String, RawEntry>,
}

/// See [`RawCache`].
const RAW_CACHE_RACY_SECS: i64 = 2;

impl RawCache {
    fn load(path: Option<&Path>) -> Self {
        path.and_then(|p| fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, path: Option<&Path>) {
        let Some(path) = path else { return };
        let tmp = path.with_extension("tmp");
        let written = serde_json::to_vec(self)
            .map_err(io::Error::other)
            .and_then(|bytes| fs::write(&tmp, bytes))
            .and_then(|()| fs::rename(&tmp, path));
        if let Err(error) = written {
            tracing::debug!(%error, path = %path.display(), "raw blob cache not saved");
        }
    }

    fn hit(&self, path: &[u8], meta: &fs::Metadata) -> Option<String> {
        let entry = self.entries.get(key_of(path).as_ref())?;
        let (dev, ino, size, mtime, ctime) = RawEntry::stat_of(meta);
        (entry.dev == dev
            && entry.ino == ino
            && entry.size == size
            && entry.mtime == mtime
            && entry.ctime == ctime)
            .then(|| entry.sha.clone())
    }

    fn record(&mut self, path: &[u8], meta: &fs::Metadata, sha: &str) {
        let key = key_of(path).into_owned();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        let (dev, ino, size, mtime, ctime) = RawEntry::stat_of(meta);
        if now - mtime.0.max(ctime.0) < RAW_CACHE_RACY_SECS {
            self.entries.remove(&key);
            return;
        }
        self.entries.insert(
            key,
            RawEntry {
                dev,
                ino,
                size,
                mtime,
                ctime,
                sha: sha.to_owned(),
            },
        );
    }

    fn retain_only<'p>(&mut self, paths: impl Iterator<Item = &'p [u8]>) {
        let keep: BTreeSet<String> = paths.map(|p| key_of(p).into_owned()).collect();
        self.entries.retain(|k, _| keep.contains(k));
    }
}

/// The closure read before packing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closure {
    /// The repository's refs, whatever their names (a ref under `refs/sealant/capture/` is the
    /// user's).
    pub refs: BTreeMap<String, String>,
    /// Symbolic refs other than `HEAD`: name → the ref it points at.
    pub symrefs: BTreeMap<String, String>,
    /// `HEAD`: its immediate target when symbolic, else a sha.
    pub head: String,
    /// The worktree tree ([`WorktreeTree::tree`]).
    pub worktree_tree: String,
    /// The raw tree ([`WorktreeTree::raw_tree`]).
    pub raw_tree: String,
    /// The index tree, when the index has no unmerged entries.
    pub index_tree: Option<String>,
    /// Every positive tip: ref values, `HEAD`, reflog entries, index, worktree and raw trees (or
    /// the index blobs when the index is unmerged), and every object a pseudo-ref or an
    /// operation's state names ([`GitRepo::operation_tips`]).
    pub tips: Vec<String>,
    /// Paths of nested repositories under the worktree (left out of the worktree tree; the
    /// chunked class carries their bytes), as [`key_of`] keys.
    pub gitlinks: Vec<String>,
    /// Paths the worktree tree could not read ([`WorktreeTree::unreadable`]).
    pub unreadable: Vec<(String, String)>,
    /// Of those, the ones carried from the previous capture's worktree tree.
    pub carried: Vec<String>,
    /// What an operation in progress needs that git cannot resolve to exactly one object
    /// ([`OperationObjects::unresolved`]).
    pub unresolved_operations: Vec<String>,
    /// The backend the repository keeps its refs in ([`GitRepo::ref_format`]).
    pub ref_format: String,
    /// Symlinks standing for `HEAD` or a ref that a restore cannot make resolve as they do
    /// here ([`GitRepo::unrestorable_ref_links`]).
    pub unrestorable_ref_links: Vec<String>,
}

/// Read the closure (refs, `HEAD`, index, stash, reflog, worktree) in that order. `excludes` are
/// pathspecs (relative to the root) left out of the worktree tree: the daemon directory.
pub fn read_closure(
    repo: &GitRepo,
    scratch_dir: &Path,
    excludes: &[String],
) -> Result<Closure, GitError> {
    read_closure_with(repo, scratch_dir, excludes, TreeOptions::default())
}

/// [`read_closure`], carrying what the worktree could not read from `carry_from` (the previous
/// capture's worktree tree; see [`GitRepo::worktree_tree_carrying`]).
pub fn read_closure_carrying(
    repo: &GitRepo,
    scratch_dir: &Path,
    excludes: &[String],
    carry_from: Option<&str>,
) -> Result<Closure, GitError> {
    read_closure_with(
        repo,
        scratch_dir,
        excludes,
        TreeOptions {
            carry_from,
            ..TreeOptions::default()
        },
    )
}

/// [`read_closure`] as `options` say ([`GitRepo::worktree_tree_with`]).
pub fn read_closure_with(
    repo: &GitRepo,
    scratch_dir: &Path,
    excludes: &[String],
    options: TreeOptions<'_>,
) -> Result<Closure, GitError> {
    let ref_format = repo.ref_format()?;
    let refs = repo.refs()?;
    let symrefs = repo.symrefs_in(&ref_format)?;
    let head = repo.head_in(&ref_format)?;
    let mut tips: Vec<String> = refs.values().cloned().collect();
    if !head.starts_with("refs/") {
        tips.push(head.clone());
    }
    tips.extend(repo.root_ref_tips(&ref_format)?);
    let unrestorable_ref_links = if ref_format == "files" {
        repo.unrestorable_ref_links(&refs, &symrefs)?
    } else {
        Vec::new()
    };
    let index_tree = repo.index_tree(scratch_dir)?;
    match &index_tree {
        Some(tree) => tips.push(tree.clone()),
        None => tips.extend(repo.index_blobs()?),
    }
    tips.extend(repo.reflog_tips()?);
    let operations = repo.operation_objects()?;
    tips.extend(operations.tips);
    let WorktreeTree {
        tree: worktree_tree,
        raw_tree,
        gitlinks,
        unreadable,
        carried,
    } = repo.worktree_tree_with(scratch_dir, excludes, options)?;
    tips.push(worktree_tree.clone());
    tips.push(raw_tree.clone());
    tips.sort();
    tips.dedup();
    Ok(Closure {
        refs,
        symrefs,
        head,
        worktree_tree,
        raw_tree,
        index_tree,
        tips,
        gitlinks,
        unreadable,
        carried,
        unresolved_operations: operations.unresolved,
        ref_format,
        unrestorable_ref_links,
    })
}

/// The tips whose objects a materialized repository got from the chain: ref values, a detached
/// `HEAD`, reflog entries. These are what a snap after a materialize may hold as negatives.
///
/// Deliberately not [`read_closure`]: that writes the index and worktree trees afresh, and
/// those objects exist only locally unless they happen to equal the chain head's pseudo-refs
/// (the head's own tips are negatives already). Seeding them as "stored" hid every tree the
/// materialized disk differed by from the next pack — observed as a capture whose root tree
/// named subtrees no pack of the chain held (`fatal: unable to read tree`).
pub fn stored_tips(repo: &GitRepo) -> Result<Vec<String>, GitError> {
    let refs = repo.refs()?;
    let head = repo.head()?;
    let mut tips: Vec<String> = refs.into_values().collect();
    if !head.starts_with("refs/") {
        tips.push(head);
    }
    tips.extend(repo.reflog_tips()?);
    tips.sort();
    tips.dedup();
    Ok(tips)
}

/// A finished, self-contained git pack with its index.
#[derive(Debug, Clone)]
pub struct FinishedGitPack {
    /// `<dir>/<sha256>`.
    pub path: PathBuf,
    /// `<dir>/<sha256>.idx`.
    pub idx_path: PathBuf,
    /// sha256 of the pack bytes.
    pub sha256: String,
    /// Pack size.
    pub bytes: u64,
    /// Object count.
    pub objects: u32,
}

/// Result of building the git class.
#[derive(Debug, Clone)]
pub struct GitPackResult {
    /// The pack, or `None` when nothing is new since the previous tips.
    pub pack: Option<FinishedGitPack>,
    /// The closure the pack corresponds to.
    pub closure: Closure,
    /// fsck outcome.
    pub fsck: FsckStatus,
    /// Attempts used.
    pub attempts: u32,
}

/// Object count from a pack header (`PACK`, version, count; big-endian).
fn pack_object_count(path: &Path) -> io::Result<u32> {
    let mut header = [0u8; 12];
    use std::os::unix::fs::FileExt;
    File::open(path)?.read_exact_at(&mut header, 0)?;
    if &header[0..4] != b"PACK" {
        return Err(io::Error::other("not a git pack"));
    }
    Ok(u32::from_be_bytes([
        header[8], header[9], header[10], header[11],
    ]))
}

fn pack_once(
    repo: &GitRepo,
    out_dir: &Path,
    tips: &[String],
    negatives: &[String],
    attempt: u32,
) -> Result<Option<FinishedGitPack>, GitError> {
    let mut input = String::new();
    for t in tips {
        input.push_str(t);
        input.push('\n');
    }
    for n in negatives {
        input.push('^');
        input.push_str(n);
        input.push('\n');
    }
    let tmp = out_dir.join(format!(".git-pack-{attempt}.pack"));
    let file = File::create(&tmp).map_err(at("create", &tmp))?;
    let args = ["pack-objects", "--revs", "--stdout", "-q"];
    let mut child = git_command(&repo.root)?
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(file))
        .stderr(Stdio::piped())
        .spawn_gated()?;
    if let Some(mut pipe) = child.take_stdin() {
        let _ = pipe.write_all(input.as_bytes());
    }
    let out = child.wait_with_output()?;
    if let Err(e) = check(&args, out) {
        fs::remove_file(&tmp).ok();
        return Err(e);
    }
    let objects = pack_object_count(&tmp)?;
    if objects == 0 {
        fs::remove_file(&tmp).ok();
        return Ok(None);
    }
    // `git index-pack <file.pack>` writes `<file>.idx` beside it and verifies the pack; git
    // 2.41+ also writes `<file>.rev`, which nothing here uses.
    let tmp_str = tmp.to_string_lossy().to_string();
    let args = ["index-pack", &tmp_str];
    check(&args, git_command(&repo.root)?.args(args).output_gated()?)?;
    fs::remove_file(tmp.with_extension("rev")).ok();
    let bytes = fs::read(&tmp)?;
    let sha256 = sha256_hex(&bytes);
    let path = out_dir.join(&sha256);
    let idx_path = out_dir.join(format!("{sha256}.idx"));
    fs::rename(&tmp, &path).map_err(at("rename into", &path))?;
    fs::rename(tmp.with_extension("idx"), &idx_path).map_err(at("rename into", &idx_path))?;
    Ok(Some(FinishedGitPack {
        path,
        idx_path,
        sha256,
        bytes: bytes.len() as u64,
        objects,
    }))
}

/// Build the git class: read the closure, pack it against `previous_tips`, re-read refs and
/// retry if anything moved or an object went missing, bounded to [`PACK_ATTEMPTS`]; after that,
/// ship the last pack with `fsck = unverified`. `excludes` are root-relative paths left out of
/// the worktree tree.
pub fn build_git_pack(
    repo: &GitRepo,
    out_dir: &Path,
    previous_tips: &[String],
    excludes: &[String],
) -> Result<GitPackResult, GitError> {
    build_git_pack_carrying(repo, out_dir, previous_tips, excludes, None)
}

/// [`build_git_pack`], carrying what the worktree could not read from `carry_from` (the
/// previous capture's worktree tree; see [`GitRepo::worktree_tree_carrying`]).
pub fn build_git_pack_carrying(
    repo: &GitRepo,
    out_dir: &Path,
    previous_tips: &[String],
    excludes: &[String],
    carry_from: Option<&str>,
) -> Result<GitPackResult, GitError> {
    build_git_pack_with(
        repo,
        out_dir,
        previous_tips,
        excludes,
        TreeOptions {
            carry_from,
            ..TreeOptions::default()
        },
    )
}

/// [`build_git_pack`] as `options` say ([`GitRepo::worktree_tree_with`]).
pub fn build_git_pack_with(
    repo: &GitRepo,
    out_dir: &Path,
    previous_tips: &[String],
    excludes: &[String],
    options: TreeOptions<'_>,
) -> Result<GitPackResult, GitError> {
    fs::create_dir_all(out_dir).map_err(at("mkdir -p", out_dir))?;
    let negatives = repo.existing(previous_tips)?;
    let mut last: Option<(Option<FinishedGitPack>, Closure)> = None;
    for attempt in 1..=PACK_ATTEMPTS {
        let closure = read_closure_with(repo, out_dir, excludes, options)?;
        let packed = match pack_once(repo, out_dir, &closure.tips, &negatives, attempt) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(attempt, error = %e, "pack-objects failed; re-reading refs");
                continue;
            }
        };
        let refs_after = repo.refs()?;
        let head_after = repo.head()?;
        let symrefs_after = repo.symrefs()?;
        let moved = symrefs_after != closure.symrefs
            || refs_after != closure.refs
            || head_after != closure.head;
        if !moved {
            let fsck = repo.fsck()?;
            return Ok(GitPackResult {
                pack: packed,
                closure,
                fsck,
                attempts: attempt,
            });
        }
        tracing::debug!(attempt, "refs moved during pack; retrying");
        if let Some(p) = &packed {
            fs::remove_file(&p.path).ok();
            fs::remove_file(&p.idx_path).ok();
        }
        last = Some((packed, closure));
    }
    // Retries exhausted: the last closure is packed once more, shipped unverified.
    let closure = match last {
        Some((_, c)) => c,
        None => read_closure_with(repo, out_dir, excludes, options)?,
    };
    let packed = pack_once(repo, out_dir, &closure.tips, &negatives, PACK_ATTEMPTS + 1)?;
    Ok(GitPackResult {
        pack: packed,
        closure,
        fsck: FsckStatus::Unverified,
        attempts: PACK_ATTEMPTS + 1,
    })
}

// ---------------------------------------------------------------------------------------------
// Materialize side.
// ---------------------------------------------------------------------------------------------

/// Whether the pack named by `sha256` is installed already (pack and index both present).
#[must_use]
pub fn pack_installed(repo: &GitRepo, sha256: &str) -> bool {
    let dir = repo.common_dir.join("objects").join("pack");
    dir.join(format!("pack-{sha256}.pack")).exists()
        && dir.join(format!("pack-{sha256}.idx")).exists()
}

/// Install a pack (and its index; regenerated with `git index-pack` when absent) into
/// `objects/pack`. `Ok(false)` when it was there already.
pub fn install_pack(
    repo: &GitRepo,
    sha256: &str,
    pack: &[u8],
    idx: Option<&[u8]>,
) -> Result<bool, GitError> {
    let dir = repo.common_dir.join("objects").join("pack");
    fs::create_dir_all(&dir).map_err(at("mkdir -p", &dir))?;
    let pack_path = dir.join(format!("pack-{sha256}.pack"));
    let idx_path = dir.join(format!("pack-{sha256}.idx"));
    if pack_path.exists() && idx_path.exists() {
        return Ok(false);
    }
    let tmp = dir.join(format!("tmp-capture-{sha256}.pack"));
    fs::write(&tmp, pack).map_err(at("write", &tmp))?;
    let tmp_idx = tmp.with_extension("idx");
    match idx {
        Some(bytes) => fs::write(&tmp_idx, bytes).map_err(at("write", &tmp_idx))?,
        None => {
            let tmp_str = tmp.to_string_lossy().to_string();
            let args = ["index-pack", &tmp_str];
            check(&args, git_command(&repo.root)?.args(args).output_gated()?)?;
            fs::remove_file(tmp.with_extension("rev")).ok();
        }
    }
    fs::rename(&tmp_idx, &idx_path).map_err(at("rename into", &idx_path))?;
    fs::rename(&tmp, &pack_path).map_err(at("rename into", &pack_path))?;
    Ok(true)
}

/// Make the repository's refs exactly `refs` (every name, as given: the caller leaves out an
/// older manifest's pseudo-refs, [`crate::manifest::GitSection::refs_to_restore`]) with `symrefs`
/// symbolic: `packed-refs` is written from the direct ones and every loose ref is removed,
/// whether the manifest names it or not, so a branch, tag, remote-tracking ref or stash the
/// disk held beyond the manifest does not survive a materialize; then each symbolic ref is
/// written loose (`packed-refs` cannot hold one) as `ref: <target>`, whether its target exists
/// or not. Directories under `refs/` a loose ref leaves empty go too, except `refs/heads` and
/// `refs/tags`, which git expects. Names and targets are [`key_of`] keys: each is written as
/// the bytes it stands for ([`bytes_of`]), so a name that is not UTF-8 comes back exactly.
///
/// A symbolic ref the repository stored as a symlink ([`symlinked_symref`]) is written here as
/// text like any other — the same ref to git — and the workspace class, which carries that
/// symlink as it was (`crate::roots`), puts the symlink back in its place afterwards.
pub fn write_packed_refs(
    repo: &GitRepo,
    refs: &BTreeMap<String, String>,
    symrefs: &BTreeMap<String, String>,
) -> Result<(), GitError> {
    for (name, target) in symrefs {
        if !is_safe_ref_name(&bytes_of(name)) || !is_safe_symref_target(&bytes_of(target)) {
            return Err(GitError::Command {
                args: "symbolic-ref".to_owned(),
                stderr: format!("refusing symbolic ref {name:?} -> {target:?}"),
            });
        }
    }
    // No `peeled` trait: this file carries no `^<peeled>` lines, and a file that claimed the
    // trait without them tells git that no ref here is an annotated tag. Git 2.43 and 2.52
    // believe it: `describe` finds no annotated tag, `show-ref -d` and the refs a fetch is
    // offered lose `v1^{}`, and 2.52's `for-each-ref %(*objectname)` fails on "bad tag".
    // Without the trait git peels each tag from its object, on every version.
    let mut text: Vec<u8> = b"# pack-refs with: sorted \n".to_vec();
    // Sorted by bytes, as git reads a `sorted` file (the keys' order is not the bytes' order
    // once one is escaped).
    let mut direct: Vec<(Vec<u8>, &String)> = refs
        .iter()
        .filter(|(name, _)| !symrefs.contains_key(*name))
        .map(|(name, sha)| (bytes_of(name).into_owned(), sha))
        .collect();
    direct.sort();
    for (name, sha) in direct {
        if !is_safe_ref_name(&name) {
            return Err(GitError::Command {
                args: "pack-refs".to_owned(),
                stderr: format!("refusing ref {:?}", key_of(&name)),
            });
        }
        text.extend_from_slice(sha.as_bytes());
        text.push(b' ');
        text.extend_from_slice(&name);
        text.push(b'\n');
    }
    let path = repo.common_dir.join("packed-refs");
    let tmp = repo.common_dir.join("packed-refs.capture-tmp");
    fs::write(&tmp, text).map_err(at("write", &tmp))?;
    fs::rename(&tmp, &path).map_err(at("rename into", &path))?;
    // After `packed-refs` holds the manifest's refs: a loose ref shadows a packed one, so none
    // may remain.
    for dir in [&repo.common_dir, &repo.git_dir] {
        remove_loose_refs(&dir.join("refs"), 0)?;
    }
    for (name, target) in symrefs {
        let name = bytes_of(name);
        // A worktree's own refs live in its git directory, the rest in the common one.
        let per_worktree = [&b"refs/bisect/"[..], b"refs/worktree/", b"refs/rewritten/"]
            .iter()
            .any(|p| name.starts_with(p));
        let base = if per_worktree {
            &repo.git_dir
        } else {
            &repo.common_dir
        };
        let path = base.join(std::ffi::OsStr::from_bytes(&name));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(at("mkdir -p", parent))?;
        }
        let mut line = b"ref: ".to_vec();
        line.extend_from_slice(&bytes_of(target));
        line.push(b'\n');
        fs::write(&path, line).map_err(at("write", &path))?;
    }
    Ok(())
}

/// A symbolic ref's target that can be written back as the file's one line: not empty, no
/// control byte. Not required to exist, nor to be under `refs/` (git reads what it reads).
fn is_safe_symref_target(target: &[u8]) -> bool {
    !target.is_empty() && !target.iter().any(|b| *b < 0x20 || *b == 0x7f)
}

/// A ref name that is safe to write as a path under the git dir: `refs/…`, components that
/// are not empty, `.`/`..`-led, or `.lock`, and no control or special bytes. Bytes of `0x80`
/// and above (a name that is not UTF-8) are allowed: git allows them.
fn is_safe_ref_name(name: &[u8]) -> bool {
    name.starts_with(b"refs/")
        && name
            .split(|b| *b == b'/')
            .all(|c| !c.is_empty() && !c.starts_with(b".") && !c.ends_with(b".lock"))
        && !name.windows(2).any(|w| w == b"..")
        && !name.iter().any(|b| {
            *b < 0x20
                || *b == 0x7f
                || matches!(b, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
}

/// Remove every file under `dir` (a `refs/` directory) and the directories that empties, but
/// `refs/` itself, `refs/heads` and `refs/tags`.
fn remove_loose_refs(dir: &Path, depth: usize) -> Result<(), GitError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(at("list", dir)(e)),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            remove_loose_refs(&path, depth + 1)?;
            let keep = depth == 0 && (entry.file_name() == "heads" || entry.file_name() == "tags");
            if !keep {
                match fs::remove_dir(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                    Err(e) => return Err(at("rmdir", &path)(e)),
                }
            }
        } else {
            fs::remove_file(&path).map_err(at("rm", &path))?;
        }
    }
    Ok(())
}

/// Write `HEAD` (a symbolic ref, a [`key_of`] key written as its bytes, or a detached sha).
/// Written beside and renamed over: a `HEAD` stored as a symlink is replaced, never written
/// through (that would write the file the link reaches — a branch — or fail on a link that
/// reaches nothing). The workspace class puts a captured symlink back afterwards.
pub fn write_head(repo: &GitRepo, head: &str) -> Result<(), GitError> {
    let mut text = Vec::new();
    if head.starts_with("refs/") {
        text.extend_from_slice(b"ref: ");
    }
    text.extend_from_slice(&bytes_of(head));
    text.push(b'\n');
    let path = repo.git_dir.join("HEAD");
    let tmp = repo.git_dir.join("HEAD.capture-tmp");
    fs::write(&tmp, text).map_err(at("write", &tmp))?;
    fs::rename(&tmp, &path).map_err(at("rename into", &path))?;
    Ok(())
}

/// Make every symlink of [`GitRepo::ref_symlinks`] that git read as a ref (its name in `refs`,
/// or `HEAD`) resolve as it did: a restore writes the refs `packed-refs`, and a symlink that
/// reached a loose ref file (`refs/heads/alias -> main`) came back reaching nothing — git then
/// reads no such ref, and falls back to no packed one (review 2026-09-28, ninth pass, #2). The
/// ref file its chain ends on is written loose with the value `refs` gives it. Returns the
/// names of the links it could not make resolve (their chain ends on no ref `refs` holds).
pub fn ground_ref_symlinks(
    repo: &GitRepo,
    refs: &BTreeMap<String, String>,
) -> Result<Vec<String>, GitError> {
    let dirs = RefDirs::of(repo);
    let mut left = Vec::new();
    for link in repo.ref_symlinks()? {
        if symlinked_symref(&link.path).is_some() || fs::metadata(&link.path).is_ok() {
            continue;
        }
        let name = key_of(&link.name).into_owned();
        if link.name != b"HEAD" && !refs.contains_key(&name) {
            continue;
        }
        let end = link_terminal(&link.path);
        let target = match end.as_deref().map(|end| dirs.place(end)) {
            Some(Place::Ref(target)) => target,
            _ => {
                left.push(name);
                continue;
            }
        };
        let (Some(end), Some(sha)) = (end, refs.get(key_of(&target).as_ref())) else {
            left.push(name);
            continue;
        };
        if let Some(parent) = end.parent() {
            fs::create_dir_all(parent).map_err(at("mkdir -p", parent))?;
        }
        fs::write(&end, format!("{sha}\n")).map_err(at("write", &end))?;
    }
    left.sort();
    Ok(left)
}

/// Write the refs, the symbolic refs and `HEAD` of a repository whose refs are not in the
/// files backend (reftable) through git, as [`write_packed_refs`] and [`write_head`] write a
/// files repository's: the repository ends with exactly `refs` (every other ref git lists is
/// deleted), `symrefs` and `head`. No reflog entry is written for any of it. A restore of
/// every class then puts the captured tables themselves in place, reflogs and all.
pub fn write_refs_through_git(
    repo: &GitRepo,
    refs: &BTreeMap<String, String>,
    symrefs: &BTreeMap<String, String>,
    head: &str,
) -> Result<(), GitError> {
    let quiet = |args: &[&OsStr]| -> Result<Command, GitError> {
        let mut c = git_command(&repo.root)?;
        c.args(["-c", "core.logAllRefUpdates=false"]).args(args);
        Ok(c)
    };
    let present = repo.run(&["for-each-ref", "--format=%(refname)"])?;
    let mut script: Vec<u8> = b"option no-deref\n".to_vec();
    for name in present
        .stdout
        .split(|b| *b == b'\n')
        .filter(|n| !n.is_empty())
    {
        let key = key_of(name);
        if !refs.contains_key(key.as_ref()) && !symrefs.contains_key(key.as_ref()) {
            script.extend_from_slice(b"delete ");
            script.extend_from_slice(name);
            script.push(b'\n');
        }
    }
    for (name, sha) in refs.iter().filter(|(n, _)| !symrefs.contains_key(*n)) {
        let name = bytes_of(name);
        if !is_safe_ref_name(&name) {
            return Err(GitError::Command {
                args: "update-ref".to_owned(),
                stderr: format!("refusing ref {:?}", key_of(&name)),
            });
        }
        script.extend_from_slice(b"update ");
        script.extend_from_slice(&name);
        script.push(b' ');
        script.extend_from_slice(sha.as_bytes());
        script.push(b'\n');
    }
    let mut child = quiet(&[OsStr::new("update-ref"), OsStr::new("--stdin")])?
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_gated()?;
    if let Some(mut pipe) = child.take_stdin() {
        let _ = pipe.write_all(&script);
    }
    check(&["update-ref", "--stdin"], child.wait_with_output()?)?;
    for (name, target) in symrefs {
        let (name, target) = (bytes_of(name), bytes_of(target));
        if !is_safe_ref_name(&name) || !is_safe_symref_target(&target) {
            return Err(GitError::Command {
                args: "symbolic-ref".to_owned(),
                stderr: format!(
                    "refusing symbolic ref {:?} -> {:?}",
                    key_of(&name),
                    key_of(&target)
                ),
            });
        }
        let out = quiet(&[
            OsStr::new("symbolic-ref"),
            OsStr::from_bytes(&name),
            OsStr::from_bytes(&target),
        ])?
        .output_gated()?;
        check(&["symbolic-ref"], out)?;
    }
    let out = if head.starts_with("refs/") {
        quiet(&[
            OsStr::new("symbolic-ref"),
            OsStr::new("HEAD"),
            OsStr::from_bytes(&bytes_of(head)),
        ])?
        .output_gated()?
    } else {
        quiet(&[
            OsStr::new("update-ref"),
            OsStr::new("--no-deref"),
            OsStr::new("HEAD"),
            OsStr::new(head),
        ])?
        .output_gated()?
    };
    check(&["HEAD"], out)?;
    Ok(())
}

/// The git a checkout runs: the user's filters smudge only when `smudge` (a tree whose blobs
/// hold cleaned bytes and no raw tree beside it); a raw tree's blobs are the bytes to write.
fn checkout_command(repo: &GitRepo, smudge: bool) -> Result<Command, GitError> {
    if smudge {
        Ok(git_command_filtering(&repo.root))
    } else {
        git_command(&repo.root)
    }
}

/// Check `tree` out into the working tree through a throwaway index: every file of the tree
/// is written (nothing is removed). The user's smudge filters run only when `smudge`. See
/// [`checkout_tree_from`] for the delta form.
pub fn checkout_tree(
    repo: &GitRepo,
    tree: &str,
    scratch_dir: &Path,
    smudge: bool,
) -> Result<(), GitError> {
    let tmp_index = scratch_index(scratch_dir)?;
    let rt = ["read-tree", tree];
    check(
        &rt,
        checkout_command(repo, smudge)?
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(rt)
            .output_gated()?,
    )?;
    let co = ["checkout-index", "-a", "-f", "-q"];
    check(
        &co,
        checkout_command(repo, smudge)?
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(co)
            .output_gated()?,
    )?;
    fs::remove_file(&tmp_index).ok();
    Ok(())
}

/// Move a working tree that holds `from` to `to` through a throwaway index: a two-tree
/// `read-tree --reset -u`, which writes the paths that differ between the trees, deletes the
/// ones `to` dropped and leaves the rest untouched (the index is trusted for them, so the
/// caller vouches that the working tree still holds `from`). Returns the number of paths the
/// tree diff names. The user's smudge filters run only when `smudge`.
pub fn checkout_tree_from(
    repo: &GitRepo,
    from: &str,
    to: &str,
    scratch_dir: &Path,
    smudge: bool,
) -> Result<u64, GitError> {
    Ok(checkout_tree_changing(repo, from, to, scratch_dir, smudge)?.len() as u64)
}

/// [`checkout_tree_from`], returning the paths the tree diff names (root-relative bytes).
pub fn checkout_tree_changing(
    repo: &GitRepo,
    from: &str,
    to: &str,
    scratch_dir: &Path,
    smudge: bool,
) -> Result<Vec<Vec<u8>>, GitError> {
    if from == to {
        return Ok(Vec::new());
    }
    let tmp_index = scratch_index(scratch_dir)?;
    let seed = ["read-tree", from];
    check(
        &seed,
        checkout_command(repo, smudge)?
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(seed)
            .output_gated()?,
    )?;
    let merge = ["read-tree", "--reset", "-u", from, to];
    check(
        &merge,
        checkout_command(repo, smudge)?
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(merge)
            .output_gated()?,
    )?;
    fs::remove_file(&tmp_index).ok();
    let diff = [
        "diff-tree",
        "-r",
        "--name-only",
        "--no-renames",
        "-z",
        from,
        to,
    ];
    let out = check(&diff, git_command(&repo.root)?.args(diff).output_gated()?)?;
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(<[u8]>::to_vec)
        .collect())
}

/// After a raw tree ([`crate::manifest::GitSection::raw_tree`]) is checked out: every regular
/// file of `tree` (of `only`, when given: the paths the checkout wrote) that git's attributes or
/// `core.autocrlf` would convert on the way out — a smudge filter, end-of-line or
/// `working-tree-encoding` conversion, an `ident` expansion — is written with its blob's bytes
/// exactly, so the working tree holds what the captured one held. A file already holding them
/// is left as it is. Returns how many were written.
pub fn restore_raw_bytes(
    repo: &GitRepo,
    tree: &str,
    only: Option<&[Vec<u8>]>,
) -> Result<u64, GitError> {
    let out = repo.run(&["ls-tree", "-r", "-z", "--full-tree", tree])?;
    let only: Option<BTreeSet<&[u8]>> = only.map(|o| o.iter().map(Vec::as_slice).collect());
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for record in out.stdout.split(|b| *b == 0) {
        let Some(tab) = record.iter().position(|b| *b == b'\t') else {
            continue;
        };
        let head = String::from_utf8_lossy(&record[..tab]).into_owned();
        let path = &record[tab + 1..];
        let mut fields = head.split(' ');
        let (Some(mode), Some(_), Some(sha)) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        if (mode == "100644" || mode == "100755") && only.as_ref().is_none_or(|o| o.contains(path))
        {
            files.push((sha.to_owned(), path.to_vec()));
        }
    }
    if files.is_empty() {
        return Ok(0);
    }
    let wanted: Vec<(String, Vec<u8>)> = if repo.autocrlf_active()? {
        files
    } else {
        let mut input: Vec<u8> = Vec::new();
        for (_, path) in &files {
            input.extend_from_slice(path);
            input.push(0);
        }
        let answer = repo.attrs_of(None, &input)?;
        let mut converted: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut fields = answer.split(|b| *b == 0);
        while let (Some(path), Some(attr), Some(value)) =
            (fields.next(), fields.next(), fields.next())
        {
            if converts(attr, value) {
                converted.insert(path.to_vec());
            }
        }
        files
            .into_iter()
            .filter(|(_, p)| converted.contains(p))
            .collect()
    };
    if wanted.is_empty() {
        return Ok(0);
    }
    let args = ["cat-file", "--batch"];
    let mut child = git_command(&repo.root)?
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_gated()?;
    let input: String = wanted.iter().map(|(sha, _)| format!("{sha}\n")).collect();
    let writer = child.take_stdin().map(|mut pipe| {
        std::thread::spawn(move || {
            let _ = pipe.write_all(input.as_bytes());
        })
    });
    let mut written = 0u64;
    let mut failure: Option<GitError> = None;
    if let Some(stdout) = child.take_stdout() {
        let mut reader = io::BufReader::new(stdout);
        for (sha, path) in &wanted {
            match read_batch_blob(&mut reader, sha) {
                Ok(bytes) => {
                    let abs = repo.root.join(OsStr::from_bytes(path));
                    match write_if_different(&abs, &bytes) {
                        Ok(true) => written += 1,
                        Ok(false) => {}
                        Err(e) => {
                            failure.get_or_insert(GitError::IoAt {
                                op: "write",
                                path: abs,
                                source: e,
                            });
                        }
                    }
                }
                Err(e) => {
                    failure.get_or_insert(e);
                    break;
                }
            }
        }
    }
    let out = child.wait_with_output()?;
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    if let Some(error) = failure {
        return Err(error);
    }
    check(&args, out)?;
    Ok(written)
}

/// One `git cat-file --batch` answer (`<sha> <type> <size>\n<bytes>\n`) for `sha`, a blob.
fn read_batch_blob(reader: &mut impl io::BufRead, sha: &str) -> Result<Vec<u8>, GitError> {
    let mut header = Vec::new();
    reader.read_until(b'\n', &mut header)?;
    let text = String::from_utf8_lossy(&header).trim().to_owned();
    let mut fields = text.split(' ');
    let (Some(oid), Some(kind), Some(size)) = (fields.next(), fields.next(), fields.next()) else {
        return Err(GitError::Command {
            args: "cat-file --batch".to_owned(),
            stderr: format!("{sha}: {text}"),
        });
    };
    let size: usize = size.parse().map_err(|_| GitError::Command {
        args: "cat-file --batch".to_owned(),
        stderr: format!("{sha}: {text}"),
    })?;
    if oid != sha || kind != "blob" {
        return Err(GitError::Command {
            args: "cat-file --batch".to_owned(),
            stderr: format!("{sha}: {text}"),
        });
    }
    let mut bytes = vec![0u8; size];
    reader.read_exact(&mut bytes)?;
    let mut newline = [0u8; 1];
    reader.read_exact(&mut newline)?;
    Ok(bytes)
}

/// Write `bytes` over the regular file `path` unless it holds them already (its mode is kept).
/// `Ok(false)` when nothing was written (the same bytes, or not a regular file).
fn write_if_different(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    match longpath::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    }
    if fs::read(path).is_ok_and(|current| current == bytes) {
        return Ok(false);
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(true)
}

/// Files under the working tree that `tree` does not have and git would not ignore, relative
/// to the root: the leftovers of an earlier checkout. Nested repositories (a lone `dir/` entry)
/// and anything under `excludes` are not listed.
pub fn untracked_against(
    repo: &GitRepo,
    tree: &str,
    scratch_dir: &Path,
    excludes: &[String],
) -> Result<Vec<String>, GitError> {
    let tmp_index = scratch_index(scratch_dir)?;
    let rt = ["read-tree", tree];
    check(
        &rt,
        git_command(&repo.root)?
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(rt)
            .output_gated()?,
    )?;
    let mut args: Vec<String> = ["ls-files", "-o", "--exclude-standard", "-z"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    for e in excludes {
        let e = e.trim_matches('/');
        if !e.is_empty() {
            args.push(format!("--exclude=/{e}/"));
        }
    }
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = check(
        &argv,
        git_command(&repo.root)?
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(&argv)
            .output_gated()?,
    )?;
    fs::remove_file(&tmp_index).ok();
    // Keys: a leftover whose name is not UTF-8 is removed under its own name.
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty() && !p.ends_with(b"/"))
        .map(|p| key_of(p).into_owned())
        .collect())
}

fn scratch_index(scratch_dir: &Path) -> Result<PathBuf, GitError> {
    fs::create_dir_all(scratch_dir).map_err(at("mkdir -p", scratch_dir))?;
    let tmp_index = scratch_dir.join("materialize-index");
    fs::remove_file(&tmp_index).ok();
    Ok(tmp_index)
}

/// Every path `tree` names — blobs, symlinks, subtrees and gitlinks — relative to the root, as
/// [`key_of`] keys (the keys the chunked classes' listings use).
pub fn tree_names(
    repo: &GitRepo,
    tree: &str,
) -> Result<std::collections::BTreeSet<String>, GitError> {
    let out = repo.run(&[
        "ls-tree",
        "-r",
        "-t",
        "-z",
        "--name-only",
        "--full-tree",
        tree,
    ])?;
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| key_of(p).into_owned())
        .collect())
}

/// Rebuild the real index from `tree` (used when the workspace class carried no index).
pub fn read_tree_into_index(repo: &GitRepo, tree: &str) -> Result<(), GitError> {
    repo.run(&["read-tree", tree]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, GitRepo) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("r");
        let repo = GitRepo::init(&root).unwrap();
        repo.run(&["config", "user.email", "t@t"]).unwrap();
        repo.run(&["config", "user.name", "t"]).unwrap();
        fs::write(root.join("a"), "a\n").unwrap();
        repo.run(&["add", "a"]).unwrap();
        repo.run(&["commit", "-q", "-m", "one"]).unwrap();
        (dir, repo)
    }

    /// A repository with no reflog (nothing ever updated a ref through git) has no tips, and
    /// asking is not an error.
    #[test]
    fn reflog_tips_of_a_repo_without_a_reflog_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let repo = GitRepo::init(&dir.path().join("r")).unwrap();
        assert!(!repo.git_dir.join("logs").exists());
        assert!(repo.reflog_tips().unwrap().is_empty());
        let (_dir, committed) = fixture();
        assert_eq!(committed.reflog_tips().unwrap().len(), 1);
    }

    #[test]
    fn closure_has_pseudo_refs_and_pack_round_trips() {
        let (dir, repo) = fixture();
        fs::write(repo.root.join("b"), "uncommitted\n").unwrap();
        let scratch = dir.path().join("scratch");
        let r = build_git_pack(&repo, &scratch, &[], &[]).unwrap();
        assert_eq!(r.fsck, FsckStatus::Verified);
        assert!(r.closure.tips.contains(&r.closure.worktree_tree));
        assert!(r.closure.index_tree.is_some());
        assert_eq!(
            r.closure.raw_tree, r.closure.worktree_tree,
            "nothing converts: the raw tree is the worktree tree"
        );
        assert!(
            r.closure.refs.contains_key("refs/heads/main")
                || r.closure.refs.contains_key("refs/heads/master")
        );
        let pack = r.pack.as_ref().unwrap();
        assert!(pack.objects >= 4);
        assert!(pack.idx_path.exists());

        // Nothing new: no pack.
        let tips = r.closure.tips.clone();
        let r2 = build_git_pack(&repo, &scratch, &tips, &[]).unwrap();
        assert!(r2.pack.is_none());

        // Materialize into a fresh repo and check the worktree tree out.
        let fresh = GitRepo::init(&dir.path().join("fresh")).unwrap();
        let bytes = fs::read(&pack.path).unwrap();
        install_pack(&fresh, &pack.sha256, &bytes, None).unwrap();
        write_packed_refs(&fresh, &r.closure.refs, &r.closure.symrefs).unwrap();
        write_head(&fresh, &r.closure.head).unwrap();
        checkout_tree(&fresh, &r.closure.worktree_tree, &scratch, true).unwrap();
        read_tree_into_index(&fresh, r.closure.index_tree.as_ref().unwrap()).unwrap();
        assert_eq!(
            fs::read_to_string(fresh.root.join("b")).unwrap(),
            "uncommitted\n"
        );
        assert_eq!(fresh.fsck().unwrap(), FsckStatus::Verified);
        assert_eq!(
            fresh.status_porcelain().unwrap(),
            repo.status_porcelain().unwrap()
        );
        assert!(
            !fresh
                .refs()
                .unwrap()
                .keys()
                .any(|k| k.starts_with("refs/sealant/"))
        );
    }

    /// A tracked file that matches `.gitignore` stays in the worktree tree, with or without an
    /// index on disk: tracked always wins, ignore rules only sort untracked paths.
    #[test]
    fn tracked_files_matching_gitignore_stay_in_the_worktree_tree() {
        let (dir, repo) = fixture();
        let root = repo.root.clone();
        fs::write(root.join(".gitignore"), "core.*\n").unwrap();
        fs::create_dir_all(root.join("tooling")).unwrap();
        fs::write(root.join("tooling/core.json"), "{}\n").unwrap();
        fs::write(root.join("core.1234"), "dump\n").unwrap();
        repo.run(&["add", "-f", ".gitignore", "tooling/core.json"])
            .unwrap();
        repo.run(&["commit", "-q", "-m", "core"]).unwrap();
        fs::write(root.join("tooling/core.json"), "{\"edited\":true}\n").unwrap();
        let scratch = dir.path().join("scratch");
        let names =
            |tree: &str| stdout_string(&repo.run(&["ls-tree", "-r", "--name-only", tree]).unwrap());

        let (tree, _) = repo.worktree_tree(&scratch, &[]).unwrap();
        let listed = names(&tree);
        assert!(listed.contains("tooling/core.json"), "{listed}");
        assert!(!listed.contains("core.1234"), "{listed}");
        let out = repo
            .run(&["show", &format!("{tree}:tooling/core.json")])
            .unwrap();
        assert_eq!(
            stdout_string(&out),
            "{\"edited\":true}",
            "the edit is in the tree"
        );

        // No index at all (a materialized base whose workspace class carried none): the tree
        // is seeded from HEAD, so the tracked file keeps its standing.
        fs::remove_file(repo.git_dir.join("index")).unwrap();
        let (tree_without_index, _) = repo.worktree_tree(&scratch, &[]).unwrap();
        assert_eq!(tree_without_index, tree);
        assert!(
            !repo.git_dir.join("index").exists(),
            "the real index is never written"
        );
        assert!(stored_tips(&repo).unwrap().iter().all(|t| t != &tree));
    }

    /// Every nested repository is named in an `:(exclude)` pathspec ahead of `git add -A`, so
    /// the add succeeds without `--ignore-errors` (git 2.52 makes a commit-less nested
    /// repository fatal even with it) alongside an ignored exclude, which is never named. The
    /// tree carries neither nested repository; both come back for the chunked class.
    #[test]
    fn nested_repositories_are_excluded_from_the_add_without_ignore_errors() {
        let (dir, repo) = fixture();
        let root = repo.root.clone();
        fs::write(root.join(".gitignore"), "ign/\n").unwrap();
        // Commit-less nested repository, one with a commit, one under an ignored directory.
        let nested_a = GitRepo::init(&root.join("vendor/x")).unwrap();
        fs::write(nested_a.root.join("v.txt"), "vendored\n").unwrap();
        let nested_b = GitRepo::init(&root.join("vendor/y")).unwrap();
        nested_b.run(&["config", "user.email", "t@t"]).unwrap();
        nested_b.run(&["config", "user.name", "t"]).unwrap();
        fs::write(nested_b.root.join("w.txt"), "committed\n").unwrap();
        nested_b.run(&["add", "w.txt"]).unwrap();
        nested_b.run(&["commit", "-q", "-m", "w"]).unwrap();
        GitRepo::init(&root.join("ign/z")).unwrap();
        fs::write(root.join("plain.txt"), "plain\n").unwrap();
        fs::create_dir_all(root.join("keep-out")).unwrap();
        fs::write(root.join("keep-out/k.txt"), "k\n").unwrap();

        assert_eq!(
            repo.nested_repositories(None).unwrap(),
            vec!["vendor/x".to_owned(), "vendor/y".to_owned()],
            "ignored nested repositories are not enumerated"
        );

        let scratch = dir.path().join("scratch");
        fs::create_dir_all(&scratch).unwrap();
        let tmp_index = scratch.join("idx");
        fs::copy(repo.git_dir.join("index"), &tmp_index).unwrap();
        let excludes = vec!["ign".to_owned(), "keep-out/".to_owned()];
        let add = repo.worktree_add_args(&tmp_index, &excludes).unwrap();
        let args = &add.pathspecs;
        assert_eq!(
            add.nested,
            vec!["vendor/x".to_owned(), "vendor/y".to_owned()]
        );
        let has = |spec: &str| args.iter().any(|a| a.as_slice() == spec.as_bytes());
        assert!(has(":(exclude,literal)vendor/x"), "{args:?}");
        assert!(has(":(exclude,literal)vendor/y"), "{args:?}");
        assert!(has(":(exclude,literal)keep-out"), "{args:?}");
        assert!(
            !args.iter().any(|a| a.starts_with(b":(exclude,literal)ign")),
            "an ignored exclude is never named: {args:?}"
        );

        // The argv works on its own: drop the flag and run it.
        let without_flag: Vec<OsString> = add
            .args
            .iter()
            .filter(|a| *a != "--ignore-errors")
            .map(OsString::from)
            .chain(std::iter::once(OsString::from("--")))
            .chain(args.iter().map(|a| OsStr::from_bytes(a).to_owned()))
            .collect();
        let out = git_command(&root)
            .unwrap()
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(&without_flag)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {without_flag:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let out = git_command(&root)
            .unwrap()
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(["ls-files", "-s"])
            .output()
            .unwrap();
        let listing = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(listing.contains("plain.txt"), "{listing}");
        assert!(!listing.contains("vendor/"), "{listing}");
        assert!(!listing.contains("keep-out"), "{listing}");
        assert!(!listing.contains("ign/"), "{listing}");

        // The helper itself: same tree, both nested repositories reported.
        let (tree, gitlinks) = repo.worktree_tree(&scratch, &excludes).unwrap();
        assert_eq!(gitlinks, vec!["vendor/x".to_owned(), "vendor/y".to_owned()]);
        let out = repo.run(&["ls-tree", "-r", "--name-only", &tree]).unwrap();
        let names = stdout_string(&out);
        assert!(names.contains("plain.txt"), "{names}");
        assert!(!names.contains("vendor"), "{names}");

        // A tracked gitlink (an embedded repository someone already added) is treated alike:
        // excluded from the add, its index entry kept, reported for the chunked class.
        repo.run(&["-c", "advice.addEmbeddedRepo=false", "add", "vendor/y"])
            .unwrap();
        assert_eq!(
            repo.nested_repositories(None).unwrap(),
            vec!["vendor/x".to_owned(), "vendor/y".to_owned()]
        );
        let (tree, gitlinks) = repo.worktree_tree(&scratch, &excludes).unwrap();
        assert_eq!(gitlinks, vec!["vendor/x".to_owned(), "vendor/y".to_owned()]);
        let out = repo.run(&["ls-tree", "-r", &tree]).unwrap();
        let entries = stdout_string(&out);
        assert!(entries.contains("160000 commit"), "{entries}");
        assert!(!entries.contains("vendor/x"), "{entries}");
    }

    /// An annotated tag restored through `packed-refs` still peels to its commit: the file
    /// never claims a peel trait it does not carry the `^` lines for (checked on the file
    /// itself, so it holds whichever git runs it), and git sees the tag as annotated.
    #[test]
    fn an_annotated_tag_in_packed_refs_still_peels() {
        let (dir, repo) = fixture();
        repo.run(&["tag", "-a", "v1", "-m", "v1"]).unwrap();
        repo.run(&["tag", "light"]).unwrap();
        let scratch = dir.path().join("scratch");
        let r = build_git_pack(&repo, &scratch, &[], &[]).unwrap();
        let fresh = GitRepo::init(&dir.path().join("fresh")).unwrap();
        let pack = r.pack.as_ref().unwrap();
        install_pack(&fresh, &pack.sha256, &fs::read(&pack.path).unwrap(), None).unwrap();
        write_packed_refs(&fresh, &r.closure.refs, &r.closure.symrefs).unwrap();
        write_head(&fresh, &r.closure.head).unwrap();

        let text = fs::read_to_string(fresh.common_dir.join("packed-refs")).unwrap();
        let header = text.lines().next().unwrap_or_default();
        let claims_peeled = header.starts_with("# pack-refs with:")
            && header
                .split_whitespace()
                .any(|t| t == "peeled" || t == "fully-peeled");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some((sha, name)) = line.split_once(' ') else {
                continue;
            };
            if line.starts_with('#') || line.starts_with('^') {
                continue;
            }
            let kind = stdout_string(&fresh.run(&["cat-file", "-t", sha]).unwrap());
            if claims_peeled && kind.trim() == "tag" {
                let peeled =
                    stdout_string(&fresh.run(&["rev-parse", &format!("{sha}^{{}}")]).unwrap());
                assert_eq!(
                    lines.get(i + 1).copied(),
                    Some(format!("^{}", peeled.trim()).as_str()),
                    "{name} is an annotated tag the peel trait leaves unpeeled:\n{text}"
                );
            }
        }

        let peel = |dir: &GitRepo| {
            stdout_string(
                &dir.run(&[
                    "for-each-ref",
                    "--format=%(refname) %(objectname) %(*objectname)",
                ])
                .unwrap(),
            )
        };
        assert_eq!(peel(&fresh), peel(&repo));
        let describe = |dir: &GitRepo| stdout_string(&dir.run(&["describe", "HEAD"]).unwrap());
        assert_eq!(describe(&fresh).trim(), "v1");
    }
}
