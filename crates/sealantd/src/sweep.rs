//! The final capture's sweep of every writer left in the workspace.
//!
//! [`crate::runtime::Runtime::final_flush`] terminates the managed process groups and sessions
//! first. A process that left its group — `setsid`, a double fork, a daemon a harness started
//! — is not in any of them and would keep writing after the last snap. This sweep finds every
//! such process from `/proc` and stops it (`SIGCONT`, `SIGTERM`, `SIGKILL` after the grace),
//! re-scanning until none is left, so a fork made meanwhile is caught too.
//!
//! What it may signal ([`Scope::detect`]):
//!
//! - **sealantd is PID 1 of its PID namespace** (`sealantd boot` as a container's entrypoint,
//!   Docker and Kubernetes): every process in the namespace, `docker exec`'d ones included
//!   (their parent is outside the namespace, so no ancestry would find them). The container is
//!   the workspace.
//! - **otherwise** (a Lambda MicroVM, where Core's agent is PID 1 and starts `sealantd boot`
//!   beside itself and `sealantctl`; `sealantd serve` under an SDK): every descendant of
//!   sealantd. sealantd is a child subreaper (`PR_SET_CHILD_SUBREAPER`), so an orphan of
//!   anything it started — however it detached — is re-parented to sealantd and stays its
//!   descendant. What sealantd never started (the VM's agent, its `sealantctl`) is not
//!   touched.
//!
//! In both, sealantd itself, its threads (never listed as processes in `/proc`), its own helpers
//! — the processes in sealantd's own process group: the capture engine's `git`, boot's helpers,
//! which it spawns without a group of their own, while every managed process gets its own group
//! — kernel threads and zombies (they write nothing) are left alone. A process that moved itself
//! into sealantd's process group on purpose would be taken for a helper.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

/// `PF_KTHREAD` in `/proc/<pid>/stat`'s flags.
const PF_KTHREAD: u64 = 0x0020_0000;

/// How long the `SIGKILL` phase waits for the last processes to go.
const KILL_WAIT: Duration = Duration::from_secs(5);

/// Between two scans.
const POLL: Duration = Duration::from_millis(25);

/// One process, as `/proc/<pid>/stat` has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcInfo {
    /// Process id.
    pub pid: i32,
    /// Parent process id.
    pub ppid: i32,
    /// Process group id.
    pub pgid: i32,
    /// State letter (`R`, `S`, `Z`, …).
    pub state: char,
    /// A kernel thread.
    pub kernel: bool,
}

/// Parse one `/proc/<pid>/stat` line.
#[must_use]
pub fn parse_stat(line: &str) -> Option<ProcInfo> {
    let pid = line.split_whitespace().next()?.parse().ok()?;
    // The command name is in parentheses and may hold spaces or parentheses: the fields
    // after it start after the last ')'.
    let rest = &line[line.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After the name: state(0) ppid(1) pgrp(2) session(3) tty_nr(4) tpgid(5) flags(6).
    let state = fields.first()?.chars().next()?;
    let ppid = fields.get(1)?.parse().ok()?;
    let pgid = fields.get(2)?.parse().ok()?;
    let flags: u64 = fields.get(6)?.parse().ok()?;
    Some(ProcInfo {
        pid,
        ppid,
        pgid,
        state,
        kernel: flags & PF_KTHREAD != 0,
    })
}

/// Every process `proc_root` lists (a process that exits while it is read is skipped).
#[must_use]
pub fn read_proc(proc_root: &Path) -> Vec<ProcInfo> {
    let Ok(dir) = std::fs::read_dir(proc_root) else {
        return Vec::new();
    };
    dir.flatten()
        .filter(|d| {
            d.file_name()
                .to_str()
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        })
        .filter_map(|d| std::fs::read_to_string(d.path().join("stat")).ok())
        .filter_map(|line| parse_stat(&line))
        .collect()
}

/// Which processes the sweep may signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Every process in sealantd's PID namespace (sealantd is its PID 1).
    Namespace,
    /// Every descendant of sealantd.
    Descendants,
}

impl Scope {
    /// [`Scope::Namespace`] when sealantd is PID 1 of its PID namespace, else
    /// [`Scope::Descendants`].
    #[must_use]
    pub fn detect() -> Self {
        if std::process::id() == 1 {
            Self::Namespace
        } else {
            Self::Descendants
        }
    }
}

/// Who is sweeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sweeper {
    /// sealantd's pid.
    pub me: i32,
    /// sealantd's process group: its own helpers.
    pub my_pgid: i32,
    /// What may be signalled.
    pub scope: Scope,
}

impl Sweeper {
    /// This process.
    #[must_use]
    pub fn this_process() -> Self {
        let me = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
        let my_pgid = nix::unistd::getpgid(None).map_or(me, nix::unistd::Pid::as_raw);
        Self {
            me,
            my_pgid,
            scope: Scope::detect(),
        }
    }

    /// The live processes of `procs` the sweep stops, `admit` narrowing them further.
    #[must_use]
    pub fn select(&self, procs: &[ProcInfo], admit: &dyn Fn(i32) -> bool) -> Vec<i32> {
        let parent: HashMap<i32, i32> = procs.iter().map(|p| (p.pid, p.ppid)).collect();
        let descends = |mut pid: i32| {
            // Bounded: a pid table read while it changes may hold a cycle.
            for _ in 0..procs.len() + 1 {
                match parent.get(&pid) {
                    Some(&ppid) if ppid == self.me => return true,
                    Some(&ppid) if ppid > 0 => pid = ppid,
                    _ => return false,
                }
            }
            false
        };
        procs
            .iter()
            .filter(|p| p.pid != self.me && !p.kernel && !matches!(p.state, 'Z' | 'X'))
            .filter(|p| p.pgid != self.my_pgid)
            .filter(|p| match self.scope {
                Scope::Namespace => true,
                Scope::Descendants => descends(p.pid),
            })
            .map(|p| p.pid)
            .filter(|&pid| admit(pid))
            .collect()
    }

    /// Stop every process [`Sweeper::select`] finds: `SIGCONT` and `SIGTERM` (unless `hard`),
    /// re-scanning until none is left or `grace` passes, then `SIGKILL`, re-scanning up to
    /// [`KILL_WAIT`]. Returns how many signalled processes there were and how many are still
    /// alive.
    pub async fn sweep(
        &self,
        grace: Duration,
        hard: bool,
        admit: &(dyn Fn(i32) -> bool + Sync),
    ) -> (usize, usize) {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        let proc_root = Path::new("/proc");
        let mut seen: HashSet<i32> = HashSet::new();
        if !hard {
            let until = Instant::now() + grace;
            loop {
                let targets = self.select(&read_proc(proc_root), admit);
                if targets.is_empty() {
                    return (seen.len(), 0);
                }
                for pid in targets {
                    if seen.insert(pid) {
                        tracing::info!(
                            pid,
                            "final capture: stopping a process outside the managed groups"
                        );
                        let _ = kill(Pid::from_raw(pid), Signal::SIGCONT);
                        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
                    }
                }
                if Instant::now() >= until {
                    break;
                }
                tokio::time::sleep(POLL).await;
            }
        }
        let until = Instant::now() + KILL_WAIT;
        loop {
            let targets = self.select(&read_proc(proc_root), admit);
            if targets.is_empty() {
                return (seen.len(), 0);
            }
            for &pid in &targets {
                seen.insert(pid);
                let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            }
            if Instant::now() >= until {
                return (seen.len(), targets.len());
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

/// Whether `pid`'s environment holds `key=value` exactly (a test narrows a sweep to the
/// processes it started, which inherit the entry).
#[must_use]
pub fn has_env_entry(pid: i32, key: &str, value: &str) -> bool {
    let entry = format!("{key}={value}");
    std::fs::read(format!("/proc/{pid}/environ"))
        .is_ok_and(|env| env.split(|b| *b == 0).any(|e| e == entry.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: i32, ppid: i32, pgid: i32) -> ProcInfo {
        ProcInfo {
            pid,
            ppid,
            pgid,
            state: 'S',
            kernel: false,
        }
    }

    #[test]
    fn stat_lines_parse_even_with_odd_names() {
        let line = "4242 (a (b) c) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 5";
        assert_eq!(
            parse_stat(line),
            Some(ProcInfo {
                pid: 4242,
                ppid: 1,
                pgid: 4242,
                state: 'S',
                kernel: false,
            })
        );
        let kthread = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 1";
        assert!(parse_stat(kthread).unwrap().kernel);
        let own = read_proc(Path::new("/proc"));
        let me = i32::try_from(std::process::id()).unwrap();
        assert!(own.iter().any(|p| p.pid == me), "this process is listed");
    }

    /// Outside a PID namespace of its own, the sweep takes sealantd's descendants — an orphan
    /// re-parented to it, and that orphan's children — and leaves sealantd, its helpers (its
    /// own process group), zombies, and everything it did not start.
    #[test]
    fn descendants_scope_takes_escaped_orphans_and_spares_the_rest() {
        let me = 100;
        let sweeper = Sweeper {
            me,
            my_pgid: 90,
            scope: Scope::Descendants,
        };
        let mut zombie = p(107, me, 107);
        zombie.state = 'Z';
        let procs = [
            p(1, 0, 1),       // the VM's agent (PID 1)
            p(50, 1, 50),     // its sealantctl
            p(me, 1, 90),     // sealantd
            p(101, me, 90),   // sealantd's git helper
            p(102, 101, 90),  // the helper's child
            p(103, me, 103),  // a managed process group
            p(104, me, 104),  // a setsid'd, double-forked writer re-parented to sealantd
            p(105, 104, 104), // its child
            p(106, 103, 106), // a grandchild in a group of its own
            zombie,
        ];
        let mut picked = sweeper.select(&procs, &|_| true);
        picked.sort_unstable();
        assert_eq!(picked, vec![103, 104, 105, 106]);
        let only = sweeper.select(&procs, &|pid| pid == 104);
        assert_eq!(only, vec![104]);
    }

    /// As PID 1 of its namespace, everything but sealantd, its helpers and kernel threads —
    /// a `docker exec`'d process, whose parent is outside the namespace (ppid 0), included.
    #[test]
    fn namespace_scope_takes_everything_but_sealantd_and_its_helpers() {
        let sweeper = Sweeper {
            me: 1,
            my_pgid: 1,
            scope: Scope::Namespace,
        };
        let mut kthread = p(2, 0, 0);
        kthread.kernel = true;
        let procs = [
            p(1, 0, 1),   // sealantd
            p(7, 1, 1),   // its git helper
            p(8, 1, 8),   // the harness
            p(9, 0, 9),   // `docker exec`
            p(10, 1, 10), // an escaped daemon
            kthread,
        ];
        let mut picked = sweeper.select(&procs, &|_| true);
        picked.sort_unstable();
        assert_eq!(picked, vec![8, 9, 10]);
    }
}
