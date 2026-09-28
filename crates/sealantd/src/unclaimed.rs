//! A standby no session ever claimed (Docker end to end, round 8, F7).
//!
//! A standby executor boots before any session exists: its launch is a standby's
//! (`standby:<id>`, [`is_standby_launch`]; the plan answers it as the executor), the launcher
//! names no worktree (`SEALANT_CAPTURE_WORKTREE_ID` unset), and the channel answers the
//! project's base under a placeholder identity it refuses every write for. A boot that names no
//! worktree under any other launch is a session's (the channel names its worktree), and its
//! harness's writes are that session's work: it is never unclaimed.
//! Its disk holds the base, its dotfiles and whatever its own boot ran — nothing of any session.
//! A session becomes its writer only through `capture.replan` (the claim) or a writer the
//! control API admits (an exec, a session opened or attached, stdin written, an SFTP bridge, a
//! forward, a bind, an execution started). Before, a claimed standby whose replan failed kept
//! its placeholder captures queued forever (the registrar answers `lease-lost` for them), its
//! final flush never completed, and the launch waited about 12 minutes, failed, and needed a
//! discard.
//!
//! The first boot of such a standby writes [`FILE`] into the capture staging directory once its
//! base is materialized, before any user code can run. The first claim or admitted writer removes it
//! — durably, before the replan touches the disk or the writer starts, and a writer is refused
//! if it cannot be removed. A final flush that finds it still there answers that there is
//! nothing to save ([`Unclaimed::release`]): no snap, no ship, the placeholder's queue dropped,
//! `complete: true` with nothing pending, and the daemon ends with
//! [`crate::runtime::EXIT_NOTHING_TO_SAVE`]; no claim or writer is admitted after that. The file
//! stays, so a recovery boot on that disk exits 76 at once as well. Once a writer was admitted
//! none of this applies again: the file is gone for good, and a disk without it (an older
//! daemon's, one whose boot named a worktree) is never nothing-to-save.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// The marker's name in the capture staging directory (`<worktree>/.sealantd/capture`).
pub const FILE: &str = "unclaimed.json";

/// The prefix of a standby's launch id (`standby:<id>`, as Mend names it and Core delivers it
/// as `SEALANT_CAPTURE_LAUNCH_ID`; the plan answers it as the executor).
pub const STANDBY_LAUNCH_PREFIX: &str = "standby:";

/// Whether `launch` declares a standby executor ([`STANDBY_LAUNCH_PREFIX`]).
#[must_use]
pub fn is_standby_launch(launch: &str) -> bool {
    launch
        .strip_prefix(STANDBY_LAUNCH_PREFIX)
        .is_some_and(|id| !id.is_empty())
}

/// What the marker records: the placeholder identity the standby booted under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placeholder {
    /// The worktree id the channel answered.
    pub worktree_id: String,
    /// The epoch it answered.
    pub epoch: u64,
    /// The launch (`plan.get`'s executor), if named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<String>,
}

fn path_in(staging_dir: &Path) -> PathBuf {
    staging_dir.join(FILE)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Write the marker (write, fsync, rename, fsync the directory).
///
/// # Errors
/// Any I/O error; the boot fails then, with nothing admitted.
pub fn record(staging_dir: &Path, placeholder: &Placeholder) -> io::Result<()> {
    fs::create_dir_all(staging_dir)?;
    let path = path_in(staging_dir);
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&serde_json::to_vec(placeholder)?)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    sync_dir(staging_dir)
}

/// The marker, when it is on this disk as [`record`] wrote it: a regular file that decodes.
/// Anything else — absent, a symlink, unreadable, undecodable — is `None`: never nothing to save.
#[must_use]
pub fn read(staging_dir: &Path) -> Option<Placeholder> {
    let path = path_in(staging_dir);
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    serde_json::from_slice(&fs::read(&path).ok()?).ok()
}

#[derive(Debug)]
enum State {
    /// No claim and no writer yet: the marker is at this path.
    Unclaimed(PathBuf),
    /// A claim or a writer was admitted (or the disk never had the marker).
    Claimed,
    /// A final flush found nothing to save: nothing is admitted again.
    Released,
}

/// Whether this executor ever admitted a session's writer, as the marker says, and the one
/// decision point between a claim or writer and a final flush that finds nothing to save.
#[derive(Debug)]
pub struct Unclaimed {
    state: Mutex<State>,
}

impl Unclaimed {
    /// The state the disk under `staging_dir` is in.
    #[must_use]
    pub fn load(staging_dir: &Path) -> Self {
        let state = match read(staging_dir) {
            Some(placeholder) => {
                tracing::info!(
                    worktree = %placeholder.worktree_id,
                    epoch = placeholder.epoch,
                    "a standby no session claimed yet: a final flush before a claim or a writer \
                     has nothing to save"
                );
                State::Unclaimed(path_in(staging_dir))
            }
            None => State::Claimed,
        };
        Self {
            state: Mutex::new(state),
        }
    }

    /// A claim or a writer is about to be admitted (`what` names it): from now on this executor
    /// may hold a session's work. The marker is removed durably first.
    ///
    /// # Errors
    /// The executor was released with nothing to save (nothing is admitted after that), or the
    /// marker could not be removed; the claim or writer must not go ahead.
    pub fn claim(&self, what: &str) -> Result<(), String> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match &*state {
            State::Claimed => Ok(()),
            State::Released => Err(format!(
                "{what} refused: this standby was released with nothing to save"
            )),
            State::Unclaimed(path) => {
                let removed = match fs::remove_file(path) {
                    Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
                    _ => path.parent().map_or(Ok(()), sync_dir),
                };
                if let Err(error) = removed {
                    return Err(format!(
                        "{what} refused: the standby's unclaimed marker {} could not be removed: \
                         {error}",
                        path.display()
                    ));
                }
                tracing::info!(
                    what,
                    "the standby is claimed: this executor may hold a session's work"
                );
                *state = State::Claimed;
                Ok(())
            }
        }
    }

    /// A final flush: `true` when no claim or writer was ever admitted — nothing on this disk is
    /// a session's, and nothing is admitted from now on. `false` otherwise (the flush runs).
    pub fn release(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match &*state {
            State::Unclaimed(_) | State::Released => {
                *state = State::Released;
                true
            }
            State::Claimed => false,
        }
    }

    /// Whether a final flush released this executor with nothing to save.
    #[must_use]
    pub fn released(&self) -> bool {
        matches!(
            *self.state.lock().unwrap_or_else(|e| e.into_inner()),
            State::Released
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholder() -> Placeholder {
        Placeholder {
            worktree_id: "standby-1".to_owned(),
            epoch: 7,
            launch: Some("standby:1".to_owned()),
        }
    }

    #[test]
    fn only_a_standby_launch_is_a_standby() {
        assert!(is_standby_launch("standby:1"));
        assert!(!is_standby_launch("standby:"));
        assert!(!is_standby_launch("launch-1"));
        assert!(!is_standby_launch("launch:standby:1"));
    }

    #[test]
    fn a_claim_removes_the_marker_and_a_final_flush_then_runs() {
        let tmp = tempfile::tempdir().unwrap();
        record(tmp.path(), &placeholder()).unwrap();
        assert_eq!(read(tmp.path()), Some(placeholder()));
        let unclaimed = Unclaimed::load(tmp.path());
        unclaimed.claim("an exec").unwrap();
        assert_eq!(read(tmp.path()), None, "the marker is gone for good");
        assert!(
            !unclaimed.release(),
            "a claimed executor's final flush runs"
        );
        assert!(
            !Unclaimed::load(tmp.path()).release(),
            "and after a restart"
        );
    }

    #[test]
    fn a_release_admits_nothing_after_it_and_keeps_the_marker() {
        let tmp = tempfile::tempdir().unwrap();
        record(tmp.path(), &placeholder()).unwrap();
        let unclaimed = Unclaimed::load(tmp.path());
        assert!(unclaimed.release());
        assert!(unclaimed.released());
        assert!(unclaimed.claim("a replan").is_err());
        assert!(unclaimed.release(), "asked again, still nothing to save");
        assert_eq!(
            read(tmp.path()),
            Some(placeholder()),
            "a recovery boot reads it"
        );
    }

    #[test]
    fn no_marker_or_a_bad_one_is_never_nothing_to_save() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!Unclaimed::load(tmp.path()).release(), "absent");
        fs::write(tmp.path().join(FILE), b"not json").unwrap();
        assert!(!Unclaimed::load(tmp.path()).release(), "undecodable");
        fs::remove_file(tmp.path().join(FILE)).unwrap();
        let elsewhere = tmp.path().join("elsewhere.json");
        fs::write(&elsewhere, serde_json::to_vec(&placeholder()).unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, tmp.path().join(FILE)).unwrap();
        assert!(!Unclaimed::load(tmp.path()).release(), "a symlink");
    }

    #[test]
    fn a_marker_that_cannot_be_removed_refuses_the_writer() {
        let tmp = tempfile::tempdir().unwrap();
        record(tmp.path(), &placeholder()).unwrap();
        let unclaimed = Unclaimed::load(tmp.path());
        // A directory in the marker's place: removing it as a file fails.
        fs::remove_file(tmp.path().join(FILE)).unwrap();
        fs::create_dir(tmp.path().join(FILE)).unwrap();
        assert!(unclaimed.claim("an exec").is_err());
        assert!(unclaimed.release(), "still unclaimed: nothing was admitted");
    }
}
