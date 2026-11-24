//! The privilege drop (§4.2 step 3) and the check that proves it.
//!
//! The container starts as UID 0 with exactly `NET_ADMIN`, `SETUID`, `SETGID` and `SETPCAP`
//! (`--cap-drop ALL --cap-add ...`). In `capabilities(7)` order, while still root:
//!
//! 1. drop every capability up to `cap_last_cap` from the bounding set (`PR_CAPBSET_DROP` needs
//!    effective `CAP_SETPCAP`, which dropping it from the bounding set does not remove);
//! 2. clear the ambient and inheritable sets (`setresuid` clears ambient but not inheritable);
//! 3. `setgroups([kvm_gid])`: the only supplementary group left is `/dev/kvm`'s;
//! 4. `setresgid(65532, 65532, 65532)`;
//! 5. `PR_SET_KEEPCAPS = 0`, then `setresuid(65532, 65532, 65532)`: the kernel empties the
//!    permitted, effective and ambient sets on leaving UID 0;
//! 6. `PR_SET_NO_NEW_PRIVS = 1`, beside Docker's `no-new-privileges:true`.
//!
//! Then [`verify`] reads `/proc/self/status` back and the runner aborts on any difference.
//!
//! Every step here acts on the calling thread (the bounding set, capability sets and
//! no-new-privileges are per thread, inherited by threads created later), so it must run before
//! the async runtime starts any thread.

use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use nix::unistd::{Gid, Uid};

use crate::sys;

/// `nonroot` in distroless images; owns the data disk and `/run/vm`.
pub const JAIL_UID: u32 = 65532;
pub const JAIL_GID: u32 = 65532;

/// `/dev/kvm`'s group, the one supplementary group the jailed process keeps. A device owned by
/// group 0 is refused: keeping root's group is not a jail. Pass `--kvm-gid` on such a host.
pub fn kvm_gid(path: &Path) -> Result<u32, JailError> {
    let meta = std::fs::metadata(path).map_err(|source| JailError::Kvm {
        path: path.display().to_string(),
        source,
    })?;
    validate_kvm_gid(meta.gid())
}

pub fn validate_kvm_gid(gid: u32) -> Result<u32, JailError> {
    if gid == 0 {
        return Err(JailError::RootKvmGroup);
    }
    Ok(gid)
}

#[derive(Debug, thiserror::Error)]
pub enum JailError {
    #[error("cannot stat {path}: {source}")]
    Kvm {
        path: String,
        source: std::io::Error,
    },
    #[error("/dev/kvm belongs to group 0; refusing to keep root's group (pass --kvm-gid)")]
    RootKvmGroup,
    #[error("{step} failed: {source}")]
    Step {
        step: &'static str,
        source: std::io::Error,
    },
    #[error("cannot read {path}: {source}")]
    Status {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {reason}")]
    Parse { path: String, reason: String },
    #[error("the jail does not hold: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    Violations(Vec<Violation>),
}

fn step(step: &'static str) -> impl FnOnce(std::io::Error) -> JailError {
    move |source| JailError::Step { step, source }
}

/// Runs the whole drop, in order. Irreversible: on error the process must exit.
pub fn drop_privileges(kvm_gid: u32) -> Result<(), JailError> {
    let last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(step("reading cap_last_cap"))?
        .trim()
        .parse::<u32>()
        .map_err(|e| JailError::Step {
            step: "parsing cap_last_cap",
            source: std::io::Error::other(e),
        })?;
    for cap in 0..=last_cap {
        sys::capbset_drop(cap).map_err(step("PR_CAPBSET_DROP"))?;
    }
    sys::ambient_clear_all().map_err(step("PR_CAP_AMBIENT_CLEAR_ALL"))?;
    sys::clear_inheritable().map_err(step("capset(inheritable = 0)"))?;
    nix::unistd::setgroups(&[Gid::from_raw(kvm_gid)]).map_err(|e| step("setgroups")(e.into()))?;
    let gid = Gid::from_raw(JAIL_GID);
    nix::unistd::setresgid(gid, gid, gid).map_err(|e| step("setresgid")(e.into()))?;
    nix::sys::prctl::set_keepcaps(false).map_err(|e| step("PR_SET_KEEPCAPS")(e.into()))?;
    let uid = Uid::from_raw(JAIL_UID);
    nix::unistd::setresuid(uid, uid, uid).map_err(|e| step("setresuid")(e.into()))?;
    nix::sys::prctl::set_no_new_privs().map_err(|e| step("PR_SET_NO_NEW_PRIVS")(e.into()))?;
    Ok(())
}

/// The lines of `/proc/<pid>/status` the jail is judged by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStatus {
    /// Real, effective, saved, filesystem.
    pub uid: [u32; 4],
    pub gid: [u32; 4],
    pub groups: Vec<u32>,
    pub no_new_privs: u32,
    pub cap_inh: u64,
    pub cap_prm: u64,
    pub cap_eff: u64,
    pub cap_bnd: u64,
    pub cap_amb: u64,
}

impl ProcStatus {
    /// Parses the text of a status file. Every field the jail is judged by must be present.
    pub fn parse(text: &str) -> Result<Self, String> {
        let field = |name: &str| -> Result<&str, String> {
            text.lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
                .map(str::trim)
                .ok_or_else(|| format!("no {name} line"))
        };
        let ids = |name: &str| -> Result<[u32; 4], String> {
            let values: Vec<u32> = field(name)?
                .split_whitespace()
                .map(|v| v.parse::<u32>().map_err(|e| format!("{name}: {e}")))
                .collect::<Result<_, _>>()?;
            values
                .try_into()
                .map_err(|v: Vec<u32>| format!("{name} has {} ids, expected 4", v.len()))
        };
        let mask = |name: &str| -> Result<u64, String> {
            u64::from_str_radix(field(name)?, 16).map_err(|e| format!("{name}: {e}"))
        };
        Ok(Self {
            uid: ids("Uid")?,
            gid: ids("Gid")?,
            groups: field("Groups")?
                .split_whitespace()
                .map(|v| v.parse::<u32>().map_err(|e| format!("Groups: {e}")))
                .collect::<Result<_, _>>()?,
            no_new_privs: field("NoNewPrivs")?
                .parse()
                .map_err(|e| format!("NoNewPrivs: {e}"))?,
            cap_inh: mask("CapInh")?,
            cap_prm: mask("CapPrm")?,
            cap_eff: mask("CapEff")?,
            cap_bnd: mask("CapBnd")?,
            cap_amb: mask("CapAmb")?,
        })
    }
}

/// One way the observed status differs from the jail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    Uid([u32; 4]),
    Gid([u32; 4]),
    Groups(Vec<u32>),
    NoNewPrivs(u32),
    Capability { set: &'static str, mask: u64 },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::Uid(ids) => write!(f, "Uid is {ids:?}, expected {JAIL_UID} for all four"),
            Violation::Gid(ids) => write!(f, "Gid is {ids:?}, expected {JAIL_GID} for all four"),
            Violation::Groups(groups) => write!(f, "Groups is {groups:?}"),
            Violation::NoNewPrivs(v) => write!(f, "NoNewPrivs is {v}, expected 1"),
            Violation::Capability { set, mask } => write!(f, "{set} is {mask:016x}, expected 0"),
        }
    }
}

/// Every difference between `status` and the jail: UID and GID `65532` in all four slots, groups
/// exactly `[kvm_gid]`, no-new-privileges set, and all five capability masks zero.
pub fn violations(status: &ProcStatus, kvm_gid: u32) -> Vec<Violation> {
    let mut out = Vec::new();
    if status.uid != [JAIL_UID; 4] {
        out.push(Violation::Uid(status.uid));
    }
    if status.gid != [JAIL_GID; 4] {
        out.push(Violation::Gid(status.gid));
    }
    if status.groups != [kvm_gid] {
        out.push(Violation::Groups(status.groups.clone()));
    }
    if status.no_new_privs != 1 {
        out.push(Violation::NoNewPrivs(status.no_new_privs));
    }
    for (set, mask) in [
        ("CapInh", status.cap_inh),
        ("CapPrm", status.cap_prm),
        ("CapEff", status.cap_eff),
        ("CapBnd", status.cap_bnd),
        ("CapAmb", status.cap_amb),
    ] {
        if mask != 0 {
            out.push(Violation::Capability { set, mask });
        }
    }
    out
}

/// Reads `path` (`/proc/self/status`, or a child's) and fails unless the jail holds.
pub fn verify(path: &Path, kvm_gid: u32) -> Result<ProcStatus, JailError> {
    let text = std::fs::read_to_string(path).map_err(|source| JailError::Status {
        path: path.display().to_string(),
        source,
    })?;
    let status = ProcStatus::parse(&text).map_err(|reason| JailError::Parse {
        path: path.display().to_string(),
        reason,
    })?;
    let found = violations(&status, kvm_gid);
    if !found.is_empty() {
        return Err(JailError::Violations(found));
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A status file as the kernel writes it for a process that holds the jail (`kvm_gid` 108).
    const JAILED: &str = "Name:\tsealant-vm-runn\nUmask:\t0022\nState:\tS (sleeping)\n\
        Tgid:\t7\nPid:\t7\nUid:\t65532\t65532\t65532\t65532\nGid:\t65532\t65532\t65532\t65532\n\
        FDSize:\t64\nGroups:\t108 \nNStgid:\t7\nThreads:\t1\nSigQ:\t0/63353\n\
        CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n\
        CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n\
        Seccomp:\t0\nSeccomp_filters:\t0\n";

    fn with(line: &str, replacement: &str) -> String {
        let start = JAILED.find(line).unwrap();
        let end = start + JAILED[start..].find('\n').unwrap();
        format!("{}{}{}", &JAILED[..start], replacement, &JAILED[end..])
    }

    fn check(text: &str) -> Vec<Violation> {
        violations(&ProcStatus::parse(text).unwrap(), 108)
    }

    #[test]
    fn a_jailed_status_passes() {
        let status = ProcStatus::parse(JAILED).unwrap();
        assert_eq!(status.uid, [65532; 4]);
        assert_eq!(status.groups, vec![108]);
        assert_eq!(status.no_new_privs, 1);
        assert!(violations(&status, 108).is_empty());
    }

    #[test]
    fn a_bounding_set_left_behind_fails() {
        // What a runner that skipped PR_CAPBSET_DROP would show after the UID change: the four
        // capabilities the container was given are still in the bounding set.
        let found = check(&with("CapBnd:", "CapBnd:\t00000000000011c0"));
        assert_eq!(
            found,
            vec![Violation::Capability {
                set: "CapBnd",
                mask: 0x11c0
            }]
        );
    }

    #[test]
    fn effective_inheritable_or_ambient_capabilities_fail() {
        for (line, set) in [
            ("CapEff:", "CapEff"),
            ("CapInh:", "CapInh"),
            ("CapAmb:", "CapAmb"),
            ("CapPrm:", "CapPrm"),
        ] {
            let found = check(&with(line, &format!("{set}:\t0000000000001000")));
            assert_eq!(
                found,
                vec![Violation::Capability { set, mask: 0x1000 }],
                "{set}"
            );
        }
    }

    #[test]
    fn no_new_privs_unset_fails() {
        assert_eq!(
            check(&with("NoNewPrivs:", "NoNewPrivs:\t0")),
            vec![Violation::NoNewPrivs(0)]
        );
    }

    #[test]
    fn a_wrong_uid_in_any_slot_fails() {
        // A saved set-user-ID still 0 lets the process become root again.
        assert_eq!(
            check(&with("Uid:", "Uid:\t65532\t65532\t0\t65532")),
            vec![Violation::Uid([65532, 65532, 0, 65532])]
        );
        assert_eq!(
            check(&with("Gid:", "Gid:\t0\t0\t0\t0")),
            vec![Violation::Gid([0; 4])]
        );
    }

    #[test]
    fn groups_must_be_exactly_the_kvm_group() {
        assert_eq!(
            check(&with("Groups:", "Groups:\t0 108")),
            vec![Violation::Groups(vec![0, 108])]
        );
        assert_eq!(
            check(&with("Groups:", "Groups:\t")),
            vec![Violation::Groups(vec![])]
        );
    }

    #[test]
    fn a_status_missing_a_field_does_not_parse() {
        let text = with("NoNewPrivs:", "");
        assert!(ProcStatus::parse(&text).unwrap_err().contains("NoNewPrivs"));
    }

    #[test]
    fn verify_reads_the_file_and_reports_every_violation() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("status");
        std::fs::write(
            &path,
            with("NoNewPrivs:", "NoNewPrivs:\t0")
                .replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000400"),
        )
        .unwrap();
        match verify(&path, 108) {
            Err(JailError::Violations(v)) => assert_eq!(v.len(), 2, "{v:?}"),
            other => panic!("expected violations, got {other:?}"),
        }
        std::fs::write(&path, JAILED).unwrap();
        assert!(verify(&path, 108).is_ok());
    }

    #[test]
    fn root_owned_kvm_is_refused() {
        assert!(matches!(validate_kvm_gid(0), Err(JailError::RootKvmGroup)));
        assert_eq!(validate_kvm_gid(108).unwrap(), 108);
    }
}
