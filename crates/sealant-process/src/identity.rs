//! Running a process as a given user (Mend's per-person layout, its ADR 0016): an execution, a
//! session or the dotfiles applier names a user, and the process starts as exactly that user —
//! the passwd entry's uid, primary group and supplementary groups (`initgroups`), its `HOME`,
//! `USER`, `LOGNAME` and `SHELL`, umask `0002`, and a private `TMPDIR` (`/tmp/u-<uid>`) and
//! `XDG_RUNTIME_DIR` (`/run/user/<uid>`), both 0700 and the user's. Every child inherits it.
//!
//! What the daemon's environment carries is filtered first ([`withheld_from_person`]): a
//! person's process never inherits the launcher's tokens or the daemon's `SEALANT_*` keys.
//!
//! The user is looked up in the parent (the passwd and group databases may allocate and take
//! locks); the forked child only makes the async-signal-safe calls `setgroups`, `setgid`,
//! `setuid` and `umask`, in that order, before `exec`. A process for which no user is named runs
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

/// Variables a person's process never inherits from the daemon's environment, by name: logins
/// and tokens the launcher's container may carry (a provider token in the environment wins over
/// the person's own login file), the daemon's own `SEALANT_*` configuration, an agent socket or
/// askpass that would sign as someone else, and the XDG base directories, which point into
/// root's home. Anything that looks like a secret by name is withheld too
/// ([`withheld_from_person`]). The caller's own overlay is not filtered: what it names, it
/// meant.
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
    "GITLAB_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
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

/// Name fragments of a secret (as the boot's passthrough filter reads them).
const SECRET_MARKERS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "APIKEY",
];

/// Whether a person's process never inherits `key` from the daemon's environment: a
/// [`WITHHELD`] name, any `SEALANT_*` name, or a name that looks like a secret (a
/// [`SECRET_MARKERS`] fragment, or ending in `_KEY`).
#[must_use]
pub fn withheld_from_person(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper.starts_with("SEALANT_")
        || WITHHELD.contains(&upper.as_str())
        || SECRET_MARKERS.iter().any(|m| upper.contains(m))
        || upper.ends_with("_KEY")
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

    /// Start `command` as this user: groups, group, user and umask set in the child before
    /// `exec`, after any setup registered before this call (a session's `setsid`).
    pub fn apply(&self, command: &mut std::process::Command) {
        let groups: Vec<libc::gid_t> = self.groups.clone();
        let (uid, gid) = (self.uid, self.gid);
        // SAFETY: the closure runs in the forked child before exec. It allocates nothing (the
        // group list was built in the parent and is only read) and calls only async-signal-safe
        // functions: setgroups, setgid, setuid and umask. setuid comes last: once it drops
        // root, the others would be refused.
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(groups.len(), groups.as_ptr()) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setgid(gid) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(uid) == -1 {
                    return Err(io::Error::last_os_error());
                }
                libc::umask(PERSON_UMASK);
                Ok(())
            });
        }
    }
}

/// `dir` as a directory owned by `uid:gid`, mode 0700; its parent made if missing. Whatever else
/// stands there (a file, a symlink someone planted) is removed and the directory made in its
/// place. The owner and mode are set through the opened directory, never through a path a
/// symlink could replace in between; if something replaces it again, the open fails and so does
/// the start, with the reason.
fn private_dir(dir: &Path, uid: u32, gid: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {
            if (meta.uid(), meta.gid(), meta.mode() & 0o7777) == (uid, gid, 0o700) {
                return Ok(());
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
    std::os::unix::fs::fchown(&opened, Some(uid), Some(gid))?;
    opened.set_permissions(std::fs::Permissions::from_mode(0o700))
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
            "SEALANT_DOTFILES_HTTP_TOKEN",
            "SEALANT_WORKSPACE_AUTH_KEY_BASE64",
            "SEALANT_CAPTURE_ENDPOINT",
            "MEND_SESSION_TOKEN",
            "NPM_TOKEN",
            "MY_SERVICE_PASSWORD",
            "STRIPE_SECRET",
            "DEPLOY_KEY",
            "AWS_ACCESS_KEY_ID",
            "SSH_AUTH_SOCK",
            "XDG_CONFIG_HOME",
        ] {
            assert!(withheld_from_person(withheld), "{withheld}");
        }
        for kept in [
            "PATH",
            "LANG",
            "TERM",
            "NODE_OPTIONS",
            "KEYBOARD",
            "COLORTERM",
        ] {
            assert!(!withheld_from_person(kept), "{kept}");
        }
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
        for dir in [file, link, fresh] {
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
