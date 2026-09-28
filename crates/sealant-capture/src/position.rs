//! Where an answer stands in this executor's own order (cross-repo decision 17, review
//! 2026-09-28, sixth pass): every `capture.status` and final `capture.flush` answer, and every
//! final seal, carries a position the executor itself assigns. Control planes order and
//! supersede capture evidence by it, never by their own wall clocks: two processes' clocks
//! disagree, and a newer failure recorded with a slower clock lost to an older complete.
//!
//! A position is `(epoch, launch, boot id, boot generation, observation)` with the chain head
//! beside it:
//!
//! - `epoch` and `launch` (the executor `plan.get` named) say whose evidence it is. Answers of
//!   different epochs or launches are different executors' and are never ordered against each
//!   other by position.
//! - `boot_id` is random per daemon process; `boot_generation` counts the daemon processes that
//!   opened this disk's staging directory (persisted there, fsynced before the first answer):
//!   a recovery boot of the same disk has a higher one. `0`: the count could not be persisted,
//!   and the boot is ordered against no other.
//! - `observation` is strictly increasing within one boot, over every answer and seal: an
//!   answer computes its content and takes its number under one lock, so a higher number never
//!   describes an older state.
//!
//! Ordering, for the consumers: same `(epoch, launch, boot_id)`: by `observation`. Same
//! `(epoch, launch)`, different boot ids, both generations above 0 and different: by
//! `(boot_generation, observation)`. Anything else (a missing field: an older daemon; the same
//! generation under two boot ids; a generation of 0) is incomparable, and incomparable or
//! contradictory evidence fails closed: no deletion, no "saved".

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// The file under the staging directory that counts the boots of this disk.
pub const BOOT_GENERATION_FILE: &str = "boot-generation";

/// One answer's position ([`crate::position`]); the epoch, the launch and the head are the
/// answer's own fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
    /// Random per daemon process.
    pub boot_id: String,
    /// The boots of this disk, this one included; 0 when it could not be persisted.
    pub boot_generation: u64,
    /// Strictly increasing within the boot, from 1.
    pub observation: u64,
}

/// Assigns positions ([`crate::position`]): one per engine, which is one per daemon process.
#[derive(Debug)]
pub struct Observer {
    boot_id: String,
    boot_generation: u64,
    last: Mutex<u64>,
}

fn random_id() -> String {
    let mut buf = [0u8; 16];
    let read = fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf));
    if read.is_err() {
        // Never fails the boot: the pid and the clock, mixed.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        buf[..8].copy_from_slice(&(nanos as u64).to_le_bytes());
        buf[8..12].copy_from_slice(&std::process::id().to_le_bytes());
    }
    hex::encode(buf)
}

/// Count one more boot in `dir` ([`BOOT_GENERATION_FILE`]): read, add one, write, fsync, rename,
/// fsync the directory. The new count.
fn next_generation(dir: &Path) -> io::Result<u64> {
    let path = dir.join(BOOT_GENERATION_FILE);
    let previous = match fs::read_to_string(&path) {
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e),
    };
    let next = previous
        .checked_add(1)
        .ok_or_else(|| io::Error::other("boot generation overflow"))?;
    fs::create_dir_all(dir)?;
    let tmp: PathBuf = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(next.to_string().as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    fs::File::open(dir)?.sync_all()?;
    Ok(next)
}

impl Observer {
    /// A new boot of the disk whose staging directory is `dir`: a fresh boot id, and the next
    /// boot generation persisted there. When it cannot be persisted, generation 0 (logged): the
    /// positions of this boot are ordered against no other boot's.
    #[must_use]
    pub fn open(dir: &Path) -> Self {
        let boot_generation = next_generation(dir).unwrap_or_else(|error| {
            tracing::error!(
                %error,
                dir = %dir.display(),
                "the boot generation could not be persisted; this boot's answers are ordered \
                 against no other boot's"
            );
            0
        });
        Self {
            boot_id: random_id(),
            boot_generation,
            last: Mutex::new(0),
        }
    }

    /// This boot's id.
    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// This boot's generation (0: not persisted).
    #[must_use]
    pub fn boot_generation(&self) -> u64 {
        self.boot_generation
    }

    /// Take the next position and build with it, under one lock: what `f` reads is at least as
    /// new as what any lower position described. `f` must not wait for anything that takes a
    /// position.
    pub fn observe<R>(&self, f: impl FnOnce(Position) -> R) -> R {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        *last += 1;
        f(Position {
            boot_id: self.boot_id.clone(),
            boot_generation: self.boot_generation,
            observation: *last,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_increase_and_boots_of_one_disk_count_up() {
        let tmp = tempfile::tempdir().unwrap();
        let first = Observer::open(tmp.path());
        let a = first.observe(|p| p);
        let b = first.observe(|p| p);
        assert_eq!(a.boot_generation, 1);
        assert_eq!((a.observation, b.observation), (1, 2));
        assert_eq!(a.boot_id, b.boot_id);
        let second = Observer::open(tmp.path());
        let c = second.observe(|p| p);
        assert_eq!(c.boot_generation, 2, "a later boot of the disk counts up");
        assert_ne!(c.boot_id, a.boot_id);
        assert_eq!(c.observation, 1);
    }

    #[test]
    fn a_generation_that_cannot_be_persisted_is_zero() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(BOOT_GENERATION_FILE), b"not a number").unwrap();
        assert_eq!(Observer::open(tmp.path()).boot_generation(), 0);
    }
}
