//! Ownership on restore (Mend's ADR 0016, the per-person layout): who owns what a materialize
//! writes, and the group bits it adds, from an owner map passed at launch. Captures record modes
//! and mtimes, never owners; ownership comes from the path and the map, so a uid can change
//! without touching a capture.
//!
//! - **The worktree, its git directory and every person's shared conversations**
//!   (`people/<id>/conversations/`) are the group's: each mode gets the owner's read, write and
//!   execute bits copied to the group (0644 → 0664, 0600 → 0660, never 0620), and a directory
//!   gets setgid, in the one `chmod` the restore already makes for the entry. Every existing capture was made by root
//!   with umask 022 (files 0644, directories 0755); restored as recorded under a default ACL they
//!   would be read-only to the group. Under `conversations/` the group also gets read and write
//!   whatever the recorded mode (Claude Code writes its transcripts 0600). No entry of the
//!   worktree is `chown`ed: it takes the group from the setgid root (owned by the change's owner,
//!   [`OwnerMap::prepare_worktree_root`]) and the default ACL by inheritance.
//! - **A person's saved directory** (`people/<id>/`, only for an id in the map) is owned by that
//!   person's uid and the group, entry by entry: a small tree. The directory itself is 0710 (the
//!   group may pass through to `conversations/`, not list or read the rest); every other entry
//!   outside `conversations/` keeps its recorded mode, so a person's own transcripts, memory and
//!   Codex databases stay theirs.
//! - Everything else (the rest of the harness home, a removed member's directory, which has no
//!   entry in the map) is restored as before: root's, at its recorded mode.
//!
//! Without a map nothing changes.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

pub use crate::index::CONVERSATIONS_DIR;
use crate::index::PEOPLE_DIR;

/// A person's saved directory itself: the group may pass through, not list or read.
pub const PERSON_DIR_MODE: u32 = 0o710;

/// Who owns what a restore writes (`SEALANT_CAPTURE_OWNER_MAP`, JSON).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerMap {
    /// The shared group every person is in (Mend's `mend`).
    pub gid: u32,
    /// The change's owner: owns the worktree root and its git directory.
    pub worktree: u32,
    /// Each current member's account id (the name of their directory under `people/`) and uid.
    #[serde(default)]
    pub people: BTreeMap<String, u32>,
}

/// Where a workspace-class path falls under an [`OwnerMap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The worktree, its git directory, a bulk directory: the group's.
    Shared,
    /// A person's saved directory itself.
    PersonDir(u32),
    /// `people/<id>/conversations` itself.
    ConversationsDir(u32),
    /// Anything under `people/<id>/conversations/`.
    Conversation(u32),
    /// Anything else under a person's saved directory.
    Person(u32),
    /// Everything else: as before.
    Plain,
}

impl OwnerMap {
    /// Parse and check a map: no uid or gid 0, every account id one plain path component, and no
    /// uid given to two account ids (one person's saved directory is never handed to another).
    pub fn parse(json: &str) -> Result<Self, String> {
        let map: Self =
            serde_json::from_str(json).map_err(|e| format!("the owner map is not valid: {e}"))?;
        map.check()?;
        Ok(map)
    }

    /// See [`Self::parse`].
    pub fn check(&self) -> Result<(), String> {
        if self.gid == 0 || self.worktree == 0 {
            return Err("the owner map names uid or gid 0: root owns nothing by the map".into());
        }
        let mut seen = std::collections::BTreeMap::new();
        for (id, uid) in &self.people {
            if let Some(other) = seen.insert(*uid, id) {
                return Err(format!(
                    "the owner map gives accounts {other} and {id} the same uid {uid}"
                ));
            }
            if id.is_empty() || id == "." || id == ".." || id.contains('/') || id.contains('\0') {
                return Err(format!(
                    "the owner map names an account id {id:?} that is not a directory name"
                ));
            }
            if *uid == 0 {
                return Err(format!("the owner map gives account {id} uid 0"));
            }
        }
        Ok(())
    }

    /// The scope of a workspace-class virtual path (`.git/…`, `tree/…`, `harness/…`).
    #[must_use]
    pub fn scope_of_workspace(&self, v: &str) -> Scope {
        let first = v.split('/').next().unwrap_or_default();
        match first {
            ".git" | "tree" => Scope::Shared,
            "harness" => v
                .strip_prefix("harness/")
                .map_or(Scope::Plain, |rel| self.scope_of_harness(rel)),
            _ => Scope::Plain,
        }
    }

    /// The scope of a path relative to the harness home.
    #[must_use]
    pub fn scope_of_harness(&self, rel: &str) -> Scope {
        let Some(rest) = rel
            .strip_prefix(PEOPLE_DIR)
            .and_then(|r| r.strip_prefix('/'))
        else {
            return Scope::Plain;
        };
        let (id, inner) = rest.split_once('/').unwrap_or((rest, ""));
        let Some(&uid) = self.people.get(id) else {
            return Scope::Plain;
        };
        if inner.is_empty() {
            return Scope::PersonDir(uid);
        }
        match inner.strip_prefix(CONVERSATIONS_DIR) {
            Some("") => Scope::ConversationsDir(uid),
            Some(under) if under.starts_with('/') => Scope::Conversation(uid),
            _ => Scope::Person(uid),
        }
    }

    /// The owner an entry of `scope` is given: `None` leaves it as the restore made it.
    #[must_use]
    pub fn owner(&self, scope: Scope) -> Option<(u32, u32)> {
        match scope {
            Scope::PersonDir(uid)
            | Scope::ConversationsDir(uid)
            | Scope::Conversation(uid)
            | Scope::Person(uid) => Some((uid, self.gid)),
            Scope::Shared | Scope::Plain => None,
        }
    }

    /// Make the worktree root the group's before anything is restored into it: owned by the
    /// change's owner and the group, with the owner's bits copied to the group, setgid, so every
    /// entry the restore and git create under it takes the group. Two calls, whatever the tree.
    pub fn prepare_worktree_root(&self, root: &Path) -> io::Result<()> {
        std::fs::create_dir_all(root)?;
        std::os::unix::fs::lchown(root, Some(self.worktree), Some(self.gid))?;
        let mode = std::fs::symlink_metadata(root)?.mode() & 0o7777;
        std::fs::set_permissions(
            root,
            std::fs::Permissions::from_mode(shared_mode(mode, true)),
        )
    }
}

/// The mode an entry of `scope` recorded `mode` is restored with.
#[must_use]
pub fn restored_mode(scope: Scope, mode: u32, dir: bool) -> u32 {
    match scope {
        Scope::Shared => shared_mode(mode, dir),
        Scope::Conversation(_) => shared_mode(mode | 0o060, dir),
        Scope::ConversationsDir(_) if dir => mode | ((mode & 0o100) >> 3) | 0o2000,
        Scope::PersonDir(_) if dir => PERSON_DIR_MODE,
        _ => mode,
    }
}

/// `mode` with the owner's read, write and execute bits copied to the group (whatever the group
/// had is kept), and setgid on a directory (a raw `chmod` would clear it).
#[must_use]
pub fn shared_mode(mode: u32, dir: bool) -> u32 {
    let mut m = mode | ((mode & 0o700) >> 3);
    if dir {
        m |= 0o2000;
    }
    m
}

/// Give `dirs` the group's default ACL (`setfacl -d`): what is created under each takes group
/// read, write and execute (`X`) from it, whatever the creating process's umask. Applied once at
/// executor preparation, on the worktree root and on the image's shared toolchain directories;
/// a directory that does not exist is skipped. One process for all of them.
pub fn apply_default_acl(dirs: &[&Path], gid: u32) -> io::Result<()> {
    let present: Vec<&Path> = dirs.iter().copied().filter(|d| d.is_dir()).collect();
    if present.is_empty() {
        return Ok(());
    }
    let out = Command::new("setfacl")
        .arg("-d")
        .arg("-m")
        .arg(format!("u::rwx,g::rwx,g:{gid}:rwx,m::rwx,o::rx"))
        .args(&present)
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "setfacl -d on {}: {}",
            present
                .iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> OwnerMap {
        OwnerMap {
            gid: 40000,
            worktree: 40012,
            people: [("acct_a".to_owned(), 40012), ("acct_b".to_owned(), 40031)].into(),
        }
    }

    #[test]
    fn a_path_s_scope_comes_from_where_it_is() {
        let m = map();
        assert_eq!(m.scope_of_workspace("tree/src/a.ts"), Scope::Shared);
        assert_eq!(m.scope_of_workspace("tree"), Scope::Shared);
        assert_eq!(m.scope_of_workspace(".git/config"), Scope::Shared);
        assert_eq!(
            m.scope_of_workspace("harness/.codex/config.toml"),
            Scope::Plain
        );
        assert_eq!(m.scope_of_workspace("harness/people"), Scope::Plain);
        assert_eq!(
            m.scope_of_workspace("harness/people/acct_a"),
            Scope::PersonDir(40012)
        );
        assert_eq!(
            m.scope_of_workspace("harness/people/acct_b/.claude/projects/x.jsonl"),
            Scope::Person(40031)
        );
        assert_eq!(
            m.scope_of_workspace("harness/people/acct_a/conversations"),
            Scope::ConversationsDir(40012)
        );
        assert_eq!(
            m.scope_of_workspace("harness/people/acct_a/conversations/s1/projects/x.jsonl"),
            Scope::Conversation(40012)
        );
        assert_eq!(
            m.scope_of_workspace("harness/people/acct_a/conversationsx"),
            Scope::Person(40012)
        );
        // A removed member has no entry in the map: restored as before.
        assert_eq!(
            m.scope_of_workspace("harness/people/acct_gone/.claude/x"),
            Scope::Plain
        );
    }

    #[test]
    fn group_bits_go_only_where_the_owner_has_them_and_only_in_shared_places() {
        let s = Scope::Shared;
        assert_eq!(restored_mode(s, 0o644, false), 0o664);
        assert_eq!(restored_mode(s, 0o755, false), 0o775);
        assert_eq!(restored_mode(s, 0o755, true), 0o2775);
        assert_eq!(restored_mode(s, 0o444, false), 0o444);
        // The owner's read is copied too: never a group that can write and not read.
        assert_eq!(restored_mode(s, 0o600, false), 0o660);
        assert_eq!(restored_mode(s, 0o700, true), 0o2770);
        assert_eq!(restored_mode(s, 0o640, false), 0o660);
        assert_eq!(restored_mode(s, 0o400, false), 0o440);
        assert_eq!(restored_mode(s, 0o200, false), 0o220);
        let c = Scope::Conversation(1);
        assert_eq!(restored_mode(c, 0o600, false), 0o660);
        assert_eq!(restored_mode(c, 0o400, false), 0o460);
        assert_eq!(restored_mode(c, 0o700, true), 0o2770);
        assert_eq!(
            restored_mode(Scope::ConversationsDir(1), 0o700, true),
            0o2710
        );
        assert_eq!(
            restored_mode(Scope::ConversationsDir(1), 0o2710, true),
            0o2710
        );
        assert_eq!(restored_mode(Scope::PersonDir(1), 0o755, true), 0o710);
        assert_eq!(restored_mode(Scope::Person(1), 0o600, false), 0o600);
        assert_eq!(restored_mode(Scope::Person(1), 0o700, true), 0o700);
        assert_eq!(restored_mode(Scope::Plain, 0o644, false), 0o644);
    }

    #[test]
    fn a_map_is_checked() {
        assert!(OwnerMap::parse(r#"{"gid":40000,"worktree":40012,"people":{"a":40012}}"#).is_ok());
        assert!(OwnerMap::parse(r#"{"gid":40000,"worktree":40012}"#).is_ok());
        for bad in [
            r#"{"gid":0,"worktree":40012}"#,
            r#"{"gid":40000,"worktree":0}"#,
            r#"{"gid":40000,"worktree":1,"people":{"a/b":2}}"#,
            r#"{"gid":40000,"worktree":1,"people":{"..":2}}"#,
            r#"{"gid":40000,"worktree":1,"people":{"a":0}}"#,
            r#"{"gid":40000,"worktree":1,"extra":1}"#,
            r#"{"gid":40000,"worktree":40012,"people":{"a":40012,"b":40012}}"#,
            "not json",
        ] {
            assert!(OwnerMap::parse(bad).is_err(), "{bad}");
        }
    }
}
