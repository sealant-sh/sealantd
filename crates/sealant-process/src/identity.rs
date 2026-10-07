//! Running a process as a given user (Mend's per-person layout, its ADR 0016): an execution, a
//! session or the dotfiles applier names a user, and the process starts as exactly that user —
//! the passwd entry's uid, primary group and supplementary groups (`initgroups`), its `HOME`,
//! `USER`, `LOGNAME` and `SHELL`, umask `0002`, a private `TMPDIR` (`/tmp/u-<uid>`) and
//! `XDG_RUNTIME_DIR` (`/run/user/<uid>`), both 0700 and the user's, and one capability,
//! [`CAP_FOWNER`] (ambient). Every child inherits it.
//!
//! What the daemon's environment carries is filtered first ([`withheld_from_person`]): a
//! person's process never inherits the launcher's tokens or the daemon's `SEALANT_*` keys.
//!
//! The user is looked up in the parent (the passwd and group databases may allocate and take
//! locks); the forked child only makes system calls, `setgroups`, `setgid`, `prctl`, `setuid`,
//! `capset` and `umask`, before `exec`. A process for which no user is named runs
//! as before.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use nix::unistd::{Gid, Uid, User};

/// The umask a person's processes run with: what they create is the group's to write.
pub const PERSON_UMASK: u32 = 0o002;

/// Variables a person's process never inherits from the daemon's environment, by name: the
/// logins a harness or `gh` would spend in place of the person's own (a provider token in the
/// environment wins over the person's login file), an agent socket or askpass that would sign as
/// someone else, and the XDG base directories, which point into root's home; and every
/// `SEALANT_*` name ([`withheld_from_person`]). Nothing else is withheld by its name: the
/// project's secrets (Mend's, through the launcher's secret environment, under any name) are
/// the project's, meant for every agent in it. The injector's declared harness keys are withheld
/// too, by the runtime (`RuntimeConfig::person_withheld`). The caller's own overlay is not
/// filtered: what it names, it meant.
pub const WITHHELD: &[&str] = &[
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
    "MEND_SESSION_TOKEN",
    "SSH_AUTH_SOCK",
    "SSH_ASKPASS",
    "GIT_ASKPASS",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
];

/// The image's environment for a person's processes (Core's images write it, sealant#330): its
/// first line is exactly [`PERSON_ENV_VERSION_LINE`], then one literal `KEY=VALUE` per line,
/// applied to every process run as a person (exec, session, the dotfiles commands) and never to
/// root. `PATH_PREPEND` goes in front of the base `PATH`. Blank lines, other `#` lines, lines
/// without `=`, names that are not variable names, the identity's own names, names a person
/// never inherits ([`withheld_from_person`]), secret-looking names ([`looks_secret`]) and lines
/// holding a NUL byte are skipped. A missing or unreadable file changes nothing; a file whose
/// first line is not that version applies nothing, and says why in the log.
pub const PERSON_ENV_FILE: &str = "/etc/sealant/person-env";

/// The first line of a [`PERSON_ENV_FILE`] this build reads.
pub const PERSON_ENV_VERSION_LINE: &str = "# person-env 1";

/// The `PATH` a person's process gets when the daemon's environment has none.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Names the identity sets ([`RunAs::env`]); an image file never overrides them.
const IDENTITY_KEYS: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
];

/// [`PERSON_ENV_FILE`]'s variables over a base `PATH` (`None`: [`DEFAULT_PATH`]).
#[must_use]
pub fn person_env(base_path: Option<&str>) -> Vec<(String, String)> {
    person_env_at(Path::new(PERSON_ENV_FILE), base_path)
}

/// [`person_env`] from the file at `path`.
#[must_use]
pub fn person_env_at(path: &Path, base_path: Option<&str>) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    match parse_person_env(&text, base_path) {
        Ok(env) => env,
        Err(reason) => {
            tracing::warn!(path = %path.display(), %reason, "person environment not applied");
            Vec::new()
        }
    }
}

/// The variables of a [`PERSON_ENV_FILE`] text, in order (a later line of one name wins where the
/// caller applies them in order); `PATH_PREPEND` becomes `PATH`, in front of `base_path`. `Err`
/// (nothing applies) when the first line is not [`PERSON_ENV_VERSION_LINE`].
pub fn parse_person_env(
    text: &str,
    base_path: Option<&str>,
) -> Result<Vec<(String, String)>, String> {
    let mut lines = text.lines();
    let first = lines.next().map(|l| l.trim_end_matches('\r'));
    if first != Some(PERSON_ENV_VERSION_LINE) {
        return Err(match first {
            Some(line) if line.starts_with("# person-env ") => format!(
                "it is version {:?}; this sealantd reads {PERSON_ENV_VERSION_LINE:?}",
                line.trim_start_matches("# person-env ")
            ),
            _ => format!("its first line is not {PERSON_ENV_VERSION_LINE:?}"),
        });
    }
    let mut out = Vec::new();
    let mut prepend: Vec<&str> = Vec::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() || line.trim_start().starts_with('#') || line.contains('\0') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let name_ok = key
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !name_ok {
            continue;
        }
        if key == "PATH_PREPEND" {
            if !value.is_empty() {
                prepend.push(value);
            }
            continue;
        }
        if key == "PATH"
            || IDENTITY_KEYS.contains(&key)
            || withheld_from_person(key)
            || looks_secret(key)
        {
            continue;
        }
        out.push((key.to_owned(), value.to_owned()));
    }
    if !prepend.is_empty() {
        let base = base_path.unwrap_or(DEFAULT_PATH);
        out.push(("PATH".to_owned(), format!("{}:{base}", prepend.join(":"))));
    }
    Ok(out)
}

/// Name fragments of a secret (as the boot's passthrough filter reads them): a name the image's
/// person environment never sets ([`looks_secret`]).
const SECRET_MARKERS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "APIKEY",
];

/// Whether a person's process never inherits `key` from the daemon's environment: a
/// [`WITHHELD`] name or any `SEALANT_*` name.
#[must_use]
pub fn withheld_from_person(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper.starts_with("SEALANT_") || WITHHELD.contains(&upper.as_str())
}

/// Whether `key` looks like a secret by its name (a [`SECRET_MARKERS`] fragment, or ending in
/// `_KEY`): the image's person environment never sets one.
#[must_use]
pub fn looks_secret(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    SECRET_MARKERS.iter().any(|m| upper.contains(m)) || upper.ends_with("_KEY")
}

/// A user a process runs as, resolved from the passwd and group databases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunAs {
    /// Login name.
    pub name: String,
    /// User id.
    pub uid: u32,
    /// Primary group id.
    pub gid: u32,
    /// Every group the user is in, the primary group included (`getgrouplist`).
    pub groups: Vec<u32>,
    /// The passwd home.
    pub home: PathBuf,
    /// The passwd login shell.
    pub shell: PathBuf,
}

impl RunAs {
    /// Look `user` up: a login name, or a decimal uid. Refused for root (a process names no user
    /// to run as root) and for a user the passwd database does not have.
    pub fn resolve(user: &str) -> Result<Self, String> {
        let user = user.trim();
        if user.is_empty() {
            return Err("the user to run as is empty".to_owned());
        }
        let entry = match user.parse::<u32>() {
            Ok(uid) => User::from_uid(Uid::from_raw(uid)),
            Err(_) => User::from_name(user),
        }
        .map_err(|e| format!("looking up user {user:?}: {e}"))?
        .ok_or_else(|| format!("no user {user:?} in the passwd database"))?;
        if entry.uid.is_root() {
            return Err(format!(
                "user {user:?} is root: name no user to run as root"
            ));
        }
        if entry.gid.as_raw() == 0 {
            return Err(format!(
                "user {user:?} has root's group as its primary group: a person never runs in it"
            ));
        }
        let name = CString::new(entry.name.as_bytes())
            .map_err(|_| format!("user {user:?} has a name with a NUL in it"))?;
        let groups: Vec<u32> = nix::unistd::getgrouplist(&name, entry.gid)
            .map_err(|e| format!("the groups of user {user:?}: {e}"))?
            .into_iter()
            .map(Gid::as_raw)
            .collect();
        if groups.contains(&0) {
            return Err(format!(
                "user {user:?} is in root's group: a person never runs in it"
            ));
        }
        Ok(Self {
            name: entry.name,
            uid: entry.uid.as_raw(),
            gid: entry.gid.as_raw(),
            groups,
            home: entry.dir,
            shell: entry.shell,
        })
    }

    /// The user's private temporary directory.
    #[must_use]
    pub fn tmpdir(&self) -> PathBuf {
        PathBuf::from(format!("/tmp/u-{}", self.uid))
    }

    /// The user's runtime directory.
    #[must_use]
    pub fn runtime_dir(&self) -> PathBuf {
        PathBuf::from(format!("/run/user/{}", self.uid))
    }

    /// The environment the user's identity sets, applied over the daemon's child environment
    /// and under the caller's own overlay (a caller may point `HOME` elsewhere on purpose).
    #[must_use]
    pub fn env(&self) -> Vec<(String, String)> {
        vec![
            ("HOME".to_owned(), self.home.to_string_lossy().into_owned()),
            ("USER".to_owned(), self.name.clone()),
            ("LOGNAME".to_owned(), self.name.clone()),
            (
                "SHELL".to_owned(),
                self.shell.to_string_lossy().into_owned(),
            ),
            (
                "TMPDIR".to_owned(),
                self.tmpdir().to_string_lossy().into_owned(),
            ),
            (
                "XDG_RUNTIME_DIR".to_owned(),
                self.runtime_dir().to_string_lossy().into_owned(),
            ),
        ]
    }

    /// Make the private `TMPDIR` and `XDG_RUNTIME_DIR`: directories, 0700, the user's. One that
    /// is there but is not a directory (a planted symlink) is replaced.
    pub fn prepare_dirs(&self) -> io::Result<()> {
        for dir in [self.tmpdir(), self.runtime_dir()] {
            private_dir(&dir, self.uid, self.gid)?;
        }
        Ok(())
    }

    /// Start `command` as this user: groups, group, user, [`CAP_FOWNER`] and umask set in the
    /// child before `exec`, after any setup registered before this call (a session's `setsid`).
    pub fn apply(&self, command: &mut std::process::Command) {
        let groups: Vec<libc::gid_t> = self.groups.clone();
        let (uid, gid) = (self.uid, self.gid);

        // SAFETY: the closure runs in the forked child before exec. It allocates nothing (the
        // group list was built in the parent and is only read) and makes only system calls:
        // setgroups, setgid, prctl, setuid, capset and umask. setuid comes after the group
        // calls (once it drops root, they would be refused); capset after setuid, which with
        // PR_SET_KEEPCAPS keeps root's permitted set for capset to narrow.
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(groups.len(), groups.as_ptr()) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setgid(gid) == -1 {
                    return Err(io::Error::last_os_error());
                }
                // Decided here, in the child, from exactly what it inherited
                // ([`fowner_withheld`]); without the capability, setuid alone clears every set.
                let fowner = libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0
                    && libc::prctl(
                        libc::PR_CAPBSET_READ,
                        libc::c_ulong::from(CAP_FOWNER),
                        0,
                        0,
                        0,
                    ) == 1;
                if fowner && libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(uid) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if fowner {
                    keep_only_fowner()?;
                }
                libc::umask(PERSON_UMASK);
                Ok(())
            });
        }
    }

    /// Run `work` on a thread of its own that reaches the filesystem as this user, and only as
    /// them: the thread's supplementary groups, filesystem gid and filesystem uid become the
    /// user's, and it gives up every capability, before `work` starts. The kernel then checks
    /// every path `work` opens, makes, links, removes or changes the mode of as this user's: a
    /// link they planted leads only where they could go themselves (never into another person's
    /// 0700 home), and what `work` makes is theirs. The process umask is not changed.
    ///
    /// The calling thread and every other thread keep their identity: the kernel holds
    /// credentials per thread, and these calls are the raw system calls (libc's `setgroups`
    /// would change every thread's). The thread exits when `work` returns, so no other work
    /// ever runs with what it gave up. A panic in `work` resumes on the caller.
    ///
    /// **`work` must never start a process.** Only the thread's filesystem identity is the
    /// user's: its real, effective and saved uid stay 0 (so the user cannot signal the daemon),
    /// and `execve` resets the filesystem uid to the effective one, so a child of this thread
    /// would run as full root while the code reads "as the person". A person's commands start
    /// from another thread, through [`RunAs::apply`]. The process gate enforces it: a spawn
    /// through [`crate::spawn`] from this thread fails ([`on_fs_user_thread`]).
    ///
    /// Changing a thread's filesystem uid makes the kernel mark the whole process
    /// non-dumpable (no core dump, `/proc/<pid>` pinned to root). That serves nothing here,
    /// and the daemon's other threads never take a person's identity (their real and effective
    /// uid, which ptrace and `/proc` check, stay root's on every thread), so once `work` has
    /// returned the caller puts back the dumpable state it found.
    ///
    /// # Errors
    /// The thread could not take the identity (a daemon without `CAP_SETUID` and `CAP_SETGID`):
    /// `work` does not run.
    pub fn as_fs_user<T: Send>(&self, work: impl FnOnce() -> T + Send) -> io::Result<T> {
        let (groups, uid, gid) = (&self.groups, self.uid, self.gid);
        let dumpable = process_dumpable();
        let joined = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    ON_FS_USER_THREAD.with(|on| on.set(true));
                    become_fs_user(groups, uid, gid)?;
                    Ok(work())
                })
                .join()
        });
        if dumpable == 1 {
            // SAFETY: as above.
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
        }
        match joined {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

thread_local! {
    /// Set on a thread [`RunAs::as_fs_user`] runs work on.
    static ON_FS_USER_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The process's dumpable state as `PR_GET_DUMPABLE` answers it: 1 dumpable, 0 not, 2 dumpable
/// as `fs.suid_dumpable` says.
#[must_use]
pub fn process_dumpable() -> i32 {
    // SAFETY: prctl takes integer arguments only.
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }
}

/// Whether the calling thread acts with a person's filesystem identity
/// ([`RunAs::as_fs_user`]): a process it started would run as root, so none may start.
#[must_use]
pub fn on_fs_user_thread() -> bool {
    ON_FS_USER_THREAD.with(std::cell::Cell::get)
}

/// On the calling thread only: the supplementary groups, filesystem gid and filesystem uid
/// become the user's, then every capability set is emptied. With a filesystem uid other than 0
/// the kernel already drops the filesystem capabilities (`CAP_DAC_OVERRIDE`, `CAP_FOWNER` and
/// the rest) from the effective set; emptying every set leaves the thread nothing of root's.
fn become_fs_user(groups: &[u32], uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: raw system calls on integers and on a slice of `gid_t` that outlives the call; each
    // changes the calling thread's credentials and nothing else.
    unsafe {
        if libc::syscall(libc::SYS_setgroups, groups.len(), groups.as_ptr()) == -1 {
            return Err(io::Error::last_os_error());
        }
        libc::syscall(libc::SYS_setfsgid, gid);
        libc::syscall(libc::SYS_setfsuid, uid);
    }
    // `setfsuid` and `setfsgid` report no failure: an invalid id (-1) changes nothing and
    // answers the current one, which must be the user's now.
    // SAFETY: as above.
    let (fsuid, fsgid) = unsafe {
        (
            libc::syscall(libc::SYS_setfsuid, u32::MAX),
            libc::syscall(libc::SYS_setfsgid, u32::MAX),
        )
    };
    if fsuid != libc::c_long::from(uid) || fsgid != libc::c_long::from(gid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the thread could not take uid {uid} and gid {gid} (it has {fsuid}:{fsgid})"),
        ));
    }
    let none = CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    if capset([none, none]) == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `capset` on the calling thread.
fn capset(data: [CapData; 2]) -> libc::c_long {
    let mut header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    // SAFETY: capset reads the header and two data words from valid, live memory.
    unsafe { libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()) }
}

/// The one capability a person's process holds, ambient so every program it runs keeps it:
/// changing the mode, times and other owner-only attributes of a file it does not own. In a
/// shared worktree every file is someone else's (restored ones are root's, a joiner's are the
/// joiner's), and package managers `chmod` what they relink (pnpm fails without it:
/// `ERR_PNPM_CMD_SHIM_CHMOD`).
///
/// It amounts to root: whoever can `chmod` any file can read and write any file (`chmod` it
/// first), and can make a setuid root binary or plant `/etc/ld.so.preload`. It adds nothing only
/// where the person already has root through a working setuid `sudo`: the gate Mend's ADR 0016
/// and Core's image probe require. So it is never granted under no-new-privileges, where `sudo`
/// cannot work ([`fowner_withheld`]); nothing else of root's is ever kept.
pub const CAP_FOWNER: u32 = 3;

/// Why a process run as a person from this thread runs without [`CAP_FOWNER`], or `None` when it
/// holds it. The child decides from what it inherits, and this reads the same facts on the
/// calling thread (no-new-privileges is per thread, inherited by threads and children made
/// after it is set): under no-new-privileges (sealantd's own, plan §18, or a Kubernetes
/// `allowPrivilegeEscalation: false`), where `sudo` cannot work and the capability would amount
/// to root; where the bounding set lacks it; and in a daemon that is not root. pnpm then fails
/// to relink bins as a person (`ERR_PNPM_CMD_SHIM_CHMOD`), and `runtime.getCapabilities` says so.
#[must_use]
pub fn fowner_withheld() -> Option<&'static str> {
    if !nix::unistd::geteuid().is_root() {
        return Some("the daemon is not root");
    }
    // SAFETY: prctl takes integer arguments only.
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privs != 0 {
        return Some(
            "no-new-privileges is set: sudo cannot work, and CAP_FOWNER would amount to root",
        );
    }
    // SAFETY: as above.
    let bounded = unsafe {
        libc::prctl(
            libc::PR_CAPBSET_READ,
            libc::c_ulong::from(CAP_FOWNER),
            0,
            0,
            0,
        )
    };
    if bounded != 1 {
        return Some("the daemon's bounding set lacks CAP_FOWNER");
    }
    None
}

/// `_LINUX_CAPABILITY_VERSION_3`: two 32-bit words per set.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// `struct __user_cap_header_struct`.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

/// `struct __user_cap_data_struct`.
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// In the child, after `setuid` kept root's permitted set (`PR_SET_KEEPCAPS`): narrow every set
/// to [`CAP_FOWNER`] and raise it as ambient, so it survives `exec` (a program without file
/// capabilities keeps its ambient set, and no secure-exec mode is entered: nothing grew). Where
/// the capability is not in the bounding set (a pod that drops it), every set is emptied instead
/// and the process runs without it. Never leaves anything else of root's: a failure to drop
/// everything fails the start.
fn keep_only_fowner() -> io::Result<()> {
    let bit = 1u32 << CAP_FOWNER;
    let set = capset;
    let none = CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    let fowner = CapData {
        effective: bit,
        permitted: bit,
        inheritable: bit,
    };
    if set([fowner, none]) == 0 {
        // SAFETY: prctl takes integer arguments only.
        let raised = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_RAISE,
                libc::c_ulong::from(CAP_FOWNER),
                0,
                0,
            )
        };
        if raised == 0 {
            return Ok(());
        }
    }
    if set([none, none]) == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `dir` as a directory owned by `uid:gid`, mode 0700; its parent made if missing. Whatever else
/// stands there (a file, a symlink someone planted) is removed and the directory made in its
/// place. The owner and mode are set through the opened directory, never through a path a
/// symlink could replace in between; if something replaces it again, the open fails and so does
/// the start, with the reason.
///
/// # Errors
/// Whatever removing, making, opening or changing the directory answers.
pub fn private_dir(dir: &Path, uid: u32, gid: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {
            if (meta.uid(), meta.gid(), meta.mode() & 0o7777) == (uid, gid, 0o700) {
                return Ok(());
            }
            // Someone else made it: whatever they planted inside goes with it (std's
            // `remove_dir_all` never follows a symlink out of the tree).
            if meta.uid() != uid {
                std::fs::remove_dir_all(dir)?;
                make_dir(dir)?;
            }
        }
        Ok(_) => {
            std::fs::remove_file(dir)?;
            make_dir(dir)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => make_dir(dir)?,
        Err(e) => return Err(e),
    }
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", dir.display())))?;
    // The mode while it is still root's, then the owner: changing the mode of a file one does
    // not own takes `CAP_FOWNER`, which a daemon in a pod that drops it lacks.
    opened.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    std::os::unix::fs::fchown(&opened, Some(uid), Some(gid))
}

/// `mkdir dir` (its parent made if missing); one made meanwhile is fine.
fn make_dir(dir: &Path) -> io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::create_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_image_s_person_environment_is_read_as_literal_lines() {
        // Core's marker and lines as its images write them (sealant#330), then the edge cases.
        let text = "# person-env 1\r\nPATH_PREPEND=/opt/npm-global/bin:/opt/pnpm/bin:/opt/pnpm\n\
                    pnpm_config_store_dir=/var/cache/pnpm/store\nnpm_config_prefix=/opt/npm-global\n\
                    MISE_DATA_DIR=/opt/mise\n# a comment\n\nnot a line\n1BAD=x\nBAD-NAME=x\n\
                    HOME=/nope\nPATH=/replaced\nSEALANT_X=y\nNPM_TOKEN=t\nNUL=a\0b\n\
                    QUOTED=\"a b\" $HOME\nEMPTY=\nMISE_DATA_DIR=/opt/mise2\n";
        assert_eq!(
            parse_person_env(text, Some("/usr/bin:/bin")).unwrap(),
            vec![
                (
                    "pnpm_config_store_dir".to_owned(),
                    "/var/cache/pnpm/store".to_owned()
                ),
                ("npm_config_prefix".to_owned(), "/opt/npm-global".to_owned()),
                ("MISE_DATA_DIR".to_owned(), "/opt/mise".to_owned()),
                ("QUOTED".to_owned(), "\"a b\" $HOME".to_owned()),
                ("EMPTY".to_owned(), String::new()),
                ("MISE_DATA_DIR".to_owned(), "/opt/mise2".to_owned()),
                (
                    "PATH".to_owned(),
                    "/opt/npm-global/bin:/opt/pnpm/bin:/opt/pnpm:/usr/bin:/bin".to_owned()
                ),
            ]
        );
        assert_eq!(
            parse_person_env("# person-env 1\nPATH_PREPEND=/a\nPATH_PREPEND=/b\n", None).unwrap(),
            vec![("PATH".to_owned(), format!("/a:/b:{DEFAULT_PATH}"))]
        );
        // A missing or unknown version applies nothing, and says why.
        for (text, why) in [
            ("# person-env 2\nA=1\n", "version \"2\""),
            ("A=1\n", "first line"),
            ("# sealant person-env 1\nA=1\n", "first line"),
            ("\n# person-env 1\nA=1\n", "first line"),
            ("", "first line"),
        ] {
            let err = parse_person_env(text, None).unwrap_err();
            assert!(err.contains(why), "{text:?}: {err}");
        }
        assert!(person_env_at(Path::new("/nonexistent/person-env"), None).is_empty());
    }

    #[test]
    fn root_and_unknown_users_are_refused() {
        assert!(RunAs::resolve("root").is_err());
        assert!(RunAs::resolve("0").is_err());
        assert!(RunAs::resolve("").is_err());
        assert!(RunAs::resolve("no-such-user-sealantd-test").is_err());
        assert!(RunAs::resolve("4294967000").is_err());
    }

    #[test]
    fn a_person_never_inherits_a_token_or_the_daemon_s_configuration() {
        for withheld in [
            "CLAUDE_CODE_OAUTH_TOKEN",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "gh_token",
            "ANTHROPIC_API_KEY",
            "SEALANT_DOTFILES_HTTP_TOKEN",
            "SEALANT_WORKSPACE_AUTH_KEY_BASE64",
            "SEALANT_CAPTURE_ENDPOINT",
            "MEND_SESSION_TOKEN",
            "SSH_AUTH_SOCK",
            "XDG_CONFIG_HOME",
        ] {
            assert!(withheld_from_person(withheld), "{withheld}");
        }
        // A project's secrets, under whatever name, are the project's: they reach its people.
        for kept in [
            "PATH",
            "LANG",
            "NPM_TOKEN",
            "STRIPE_SECRET_KEY",
            "DATABASE_PASSWORD",
            "DEPLOY_KEY",
            "AWS_ACCESS_KEY_ID",
        ] {
            assert!(!withheld_from_person(kept), "{kept}");
        }
        for secret in [
            "NPM_TOKEN",
            "STRIPE_SECRET_KEY",
            "DATABASE_PASSWORD",
            "DEPLOY_KEY",
        ] {
            assert!(looks_secret(secret), "{secret}");
        }
        assert!(!looks_secret("MISE_DATA_DIR"));
    }

    /// A file (or a symlink) squatting a user's private directory is replaced by the directory,
    /// on the first try.
    #[test]
    fn a_squatted_private_directory_is_made_in_its_place() {
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid) = (
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
        );
        let file = tmp.path().join("u-file");
        std::fs::write(&file, "squat").unwrap();
        private_dir(&file, uid, gid).unwrap();
        let link = tmp.path().join("u-link");
        std::os::unix::fs::symlink(tmp.path(), &link).unwrap();
        private_dir(&link, uid, gid).unwrap();
        let fresh = tmp.path().join("a/u-fresh");
        private_dir(&fresh, uid, gid).unwrap();
        // A directory of the user's own with another mode keeps what is in it.
        let own = tmp.path().join("u-own");
        std::fs::create_dir(&own).unwrap();
        std::fs::write(own.join("kept"), "x").unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_dir(&own, uid, gid).unwrap();
        assert!(own.join("kept").exists());
        for dir in [file, link, fresh, own] {
            let meta = std::fs::symlink_metadata(&dir).unwrap();
            assert!(meta.is_dir(), "{}", dir.display());
            assert_eq!(meta.mode() & 0o7777, 0o700);
            assert_eq!(meta.uid(), uid);
        }
        assert!(tmp.path().is_dir(), "the symlink's target was left alone");
    }

    #[test]
    fn the_current_user_resolves_with_their_groups_and_home() {
        let me = nix::unistd::getuid();
        if me.is_root() {
            return;
        }
        let user = RunAs::resolve(&me.as_raw().to_string()).unwrap();
        assert_eq!(user.uid, me.as_raw());
        assert!(user.groups.contains(&user.gid));
        let by_name = RunAs::resolve(&user.name).unwrap();
        assert_eq!(by_name, user);
        let env = user.env();
        assert!(env.contains(&("USER".to_owned(), user.name.clone())));
        assert!(env.contains(&("TMPDIR".to_owned(), format!("/tmp/u-{}", user.uid))));
    }
}
