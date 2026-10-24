//! Who holds the far end of a bound forward's connection.
//!
//! A forward bound to a session opens only when the socket that accepted sealantd's connection
//! is held by the session's processes and by no other process. sealantd knows its own end of the
//! connection, so the target's end is the established socket with the reverse tuple in
//! `/proc/net/tcp{,6}`, which gives its inode and the uid of the listener that accepted it. The
//! holders are the processes of that uid with an fd on that inode. A holder belongs to the
//! session when it shares the leader's Linux session id, or when it runs as the leader's user and
//! group and the first [`SESSION_ENV`] entry of its environment is the session's secret marker,
//! which covers a server that called `setsid` or double-forked.
//!
//! Each process is read through one handle on its `/proc/<pid>` directory, so a pid that a new
//! process takes over midway reads as gone, never as the newcomer. A process of another user is
//! read on a thread with that user's filesystem ids
//! ([`sealant_process::identity::as_proc_reader`]), one thread per user and group.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, OwnedFd};
use std::time::{Duration, Instant};

use nix::dir::Dir;
use nix::fcntl::{OFlag, open, openat, readlinkat};
use nix::sys::stat::Mode;
use sealant_protocol::{ControlError, ControlErrorCode, ForwardBindingRefusal, SESSION_ENV};

/// The first wait between looks, doubled after each up to [`LONGEST_WAIT`]: a server usually
/// accepts within a millisecond of the connect.
const FIRST_WAIT: Duration = Duration::from_millis(1);
const LONGEST_WAIT: Duration = Duration::from_millis(50);

/// Looks that may find the accepted socket and no holder. accept puts the socket in the
/// server's fd table at once, so a holder still missing after these is outside sealantd's view.
const LOOKS_WITHOUT_HOLDER: u32 = 3;

/// The error a refused bound forward answers with.
#[must_use]
pub fn refusal_error(refusal: ForwardBindingRefusal, session_id: &str) -> ControlError {
    let (code, message) = match refusal {
        ForwardBindingRefusal::OwnerExited => (
            ControlErrorCode::SessionNotFound,
            format!("session {session_id} is not running"),
        ),
        ForwardBindingRefusal::PeerMismatch => (
            ControlErrorCode::PolicyDenied,
            format!("a process outside session {session_id} holds the forward's target"),
        ),
        ForwardBindingRefusal::Unverifiable => (
            ControlErrorCode::PolicyDenied,
            format!("could not confirm that session {session_id} holds the forward's target"),
        ),
    };
    ControlError::new(code, message).with_detail(refusal.detail())
}

/// What a process is, as its `/proc` entries say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Its Linux session id.
    pub sid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// The parts of `/proc` the check reads. A `Process` is a handle on one process: every read
/// through it is of that process, or fails once it is gone.
pub trait ProcFs: Sync {
    type Process: Send + Sync;
    /// The text of `/proc/net/tcp`, or of `/proc/net/tcp6` when `v6`.
    fn tcp_table(&self, v6: bool) -> io::Result<String>;
    fn pids(&self) -> io::Result<Vec<i32>>;
    fn open(&self, pid: i32) -> io::Result<Self::Process>;
    fn identity(&self, process: &Self::Process) -> io::Result<Identity>;
    /// Run `read` where the processes of `uid` and `gid` can be read.
    ///
    /// # Errors
    /// The reads could not be set up; `read` does not run.
    fn as_reader<T: Send>(
        &self,
        uid: u32,
        gid: u32,
        read: impl FnOnce() -> T + Send,
    ) -> io::Result<T>;
    /// The inodes of the sockets among the process's fds.
    fn socket_inodes(&self, process: &Self::Process) -> io::Result<Vec<u64>>;
    /// The bytes of the process's environment.
    fn environ(&self, process: &Self::Process) -> io::Result<Vec<u8>>;
}

/// One TCP connection as sealantd holds it: its own address and the target's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connection {
    pub local: SocketAddr,
    pub peer: SocketAddr,
}

/// The session a forward is bound to, as the check needs it.
#[derive(Clone, Copy, Debug)]
pub struct Owner<'a> {
    /// The leader's pid, which is also its Linux session id (it called `setsid`).
    pub leader_pid: i32,
    /// The user and group the leader runs as.
    pub uid: u32,
    pub gid: u32,
    /// The secret the session's processes carry in [`SESSION_ENV`].
    pub marker: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Look {
    Verified,
    Refused(ForwardBindingRefusal),
    /// The connection is still in the listener's accept queue.
    NotAccepted,
    /// The accepted socket has no holder sealantd can see.
    NoHolder,
}

/// What one process of the socket's uid turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Finding {
    NotHolding,
    Member,
    Foreign,
    /// It holds the socket, and whether it is the session's could not be read.
    UnknownHolder,
    /// Its fds could not be read, so whether it holds the socket is not known.
    Unreadable,
}

/// Check, and look again while the connection waits to be accepted, all by `deadline`.
///
/// # Errors
/// [`ForwardBindingRefusal::PeerMismatch`] when a holder is outside the session;
/// [`ForwardBindingRefusal::Unverifiable`] when no holder was found by the deadline, or one
/// could not be checked.
pub fn verify(
    fs: &impl ProcFs,
    connection: Connection,
    owner: Owner<'_>,
    deadline: Instant,
) -> Result<(), ForwardBindingRefusal> {
    let mut wait = FIRST_WAIT;
    let mut without_holder = 0;
    loop {
        match look(fs, connection, owner, deadline) {
            Look::Verified => return Ok(()),
            Look::Refused(refusal) => return Err(refusal),
            Look::NotAccepted => {}
            Look::NoHolder => {
                without_holder += 1;
                if without_holder >= LOOKS_WITHOUT_HOLDER {
                    return Err(ForwardBindingRefusal::Unverifiable);
                }
            }
        }
        if Instant::now() + wait >= deadline {
            return Err(ForwardBindingRefusal::Unverifiable);
        }
        std::thread::sleep(wait);
        wait = (wait * 2).min(LONGEST_WAIT);
    }
}

fn look<F: ProcFs>(fs: &F, connection: Connection, owner: Owner<'_>, deadline: Instant) -> Look {
    let unverifiable = Look::Refused(ForwardBindingRefusal::Unverifiable);
    let Some(accepted) = accepted_socket(fs, connection) else {
        return Look::NotAccepted;
    };
    let Ok(pids) = fs.pids() else {
        return unverifiable;
    };
    let mut findings = Vec::new();
    let mut by_group: BTreeMap<u32, Vec<(F::Process, Identity)>> = BTreeMap::new();
    for pid in pids {
        if Instant::now() >= deadline {
            return unverifiable;
        }
        let read = fs
            .open(pid)
            .and_then(|process| Ok((fs.identity(&process)?, process)));
        match read {
            Ok((identity, process)) if identity.uid == accepted.uid => {
                by_group
                    .entry(identity.gid)
                    .or_default()
                    .push((process, identity));
            }
            Ok(_) => {}
            Err(e) if gone(&e) => {}
            Err(_) => findings.push(Finding::Unreadable),
        }
    }
    for (gid, group) in &by_group {
        let read = fs.as_reader(accepted.uid, *gid, || {
            group
                .iter()
                .map(|(process, identity)| {
                    (Instant::now() < deadline)
                        .then(|| find(fs, process, *identity, accepted.inode, owner))
                })
                .collect::<Option<Vec<Finding>>>()
        });
        match read {
            Ok(Some(found)) => findings.extend(found),
            Ok(None) => return unverifiable,
            Err(_) => findings.extend(group.iter().map(|_| Finding::Unreadable)),
        }
    }
    verdict(&findings)
}

fn find<F: ProcFs>(
    fs: &F,
    process: &F::Process,
    identity: Identity,
    inode: u64,
    owner: Owner<'_>,
) -> Finding {
    match fs.socket_inodes(process) {
        Err(e) if gone(&e) => Finding::NotHolding,
        Err(_) => Finding::Unreadable,
        Ok(inodes) if !inodes.contains(&inode) => Finding::NotHolding,
        Ok(_) if identity.sid == owner.leader_pid => Finding::Member,
        Ok(_) if (identity.uid, identity.gid) != (owner.uid, owner.gid) => Finding::Foreign,
        Ok(_) => match fs.environ(process) {
            Ok(environ) if first_marker(&environ) == Some(owner.marker.as_bytes()) => {
                Finding::Member
            }
            Ok(_) => Finding::Foreign,
            Err(_) => Finding::UnknownHolder,
        },
    }
}

fn verdict(findings: &[Finding]) -> Look {
    let any = |wanted: Finding| findings.contains(&wanted);
    if any(Finding::Foreign) {
        Look::Refused(ForwardBindingRefusal::PeerMismatch)
    } else if any(Finding::UnknownHolder) {
        Look::Refused(ForwardBindingRefusal::Unverifiable)
    } else if any(Finding::Member) {
        // An fd table that cannot be read does not undo a member's holding: a non-dumpable
        // `ssh-agent` of the same user is unreadable to that user, and would refuse every forward.
        Look::Verified
    } else if any(Finding::Unreadable) {
        Look::Refused(ForwardBindingRefusal::Unverifiable)
    } else {
        Look::NoHolder
    }
}

fn gone(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
        || error.raw_os_error() == Some(nix::errno::Errno::ESRCH as i32)
}

/// The established socket with the connection's reverse tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Accepted {
    inode: u64,
    uid: u32,
}

fn accepted_socket(fs: &impl ProcFs, connection: Connection) -> Option<Accepted> {
    let want_local = canonical(connection.peer);
    let want_remote = canonical(connection.local);
    [false, true]
        .into_iter()
        .filter_map(|v6| fs.tcp_table(v6).ok())
        .flat_map(|table| parse_tcp_table(&table))
        .find(|entry| {
            entry.established
                && canonical(entry.local) == want_local
                && canonical(entry.remote) == want_remote
        })
        // A socket still in the accept queue has no inode yet.
        .filter(|entry| entry.inode != 0)
        .map(|entry| Accepted {
            inode: entry.inode,
            uid: entry.uid,
        })
}

/// An IPv4 connection accepted by a dual-stack listener shows in `tcp6` as `::ffff:a.b.c.d`.
fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TcpEntry {
    local: SocketAddr,
    remote: SocketAddr,
    established: bool,
    uid: u32,
    inode: u64,
}

/// The rows of `/proc/net/tcp` or `tcp6`. A row reads
/// `sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode …`.
fn parse_tcp_table(text: &str) -> Vec<TcpEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            Some(TcpEntry {
                local: parse_proc_addr(fields.get(1)?)?,
                remote: parse_proc_addr(fields.get(2)?)?,
                established: *fields.get(3)? == "01",
                uid: fields.get(7)?.parse().ok()?,
                inode: fields.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// `0100007F:1F90` (IPv4) or 32 hex digits and a port (IPv6). The kernel prints each 32-bit
/// word of the address as the host reads it, so the bytes come back in host order.
fn parse_proc_addr(text: &str) -> Option<SocketAddr> {
    let (addr, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        let hex = addr.get(i * 8..i * 8 + 8)?;
        Some(u32::from_str_radix(hex, 16).ok()?.to_ne_bytes())
    };
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// The Linux session id in a `/proc/<pid>/stat` line: the fourth field after the command name,
/// which is in parentheses and may hold spaces or parentheses itself.
fn linux_session_of(stat: &str) -> Option<i32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(3)?.parse().ok()
}

/// The real uid and gid in `/proc/<pid>/status`.
fn ids_of(status: &str) -> Option<(u32, u32)> {
    let id = |key: &str| -> Option<u32> {
        let line = status.lines().find(|line| line.starts_with(key))?;
        line.split_whitespace().nth(1)?.parse().ok()
    };
    Some((id("Uid:")?, id("Gid:")?))
}

/// The value of the first [`SESSION_ENV`] entry, as `getenv` would find it.
fn first_marker(environ: &[u8]) -> Option<&[u8]> {
    let key = SESSION_ENV.as_bytes();
    environ.split(|&b| b == 0).find_map(|entry| {
        entry
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix(b"="))
    })
}

/// The running system's `/proc`.
#[derive(Clone, Copy, Debug, Default)]
pub struct LiveProcFs;

/// A handle on one process's `/proc/<pid>` directory.
#[derive(Debug)]
pub struct LiveProcess {
    dir: OwnedFd,
}

fn read_at(dir: &impl AsFd, name: &str) -> io::Result<Vec<u8>> {
    let fd = openat(dir, name, OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty())?;
    let mut bytes = Vec::new();
    std::fs::File::from(fd).read_to_end(&mut bytes)?;
    Ok(bytes)
}

impl ProcFs for LiveProcFs {
    type Process = LiveProcess;

    fn tcp_table(&self, v6: bool) -> io::Result<String> {
        std::fs::read_to_string(if v6 {
            "/proc/net/tcp6"
        } else {
            "/proc/net/tcp"
        })
    }

    fn pids(&self) -> io::Result<Vec<i32>> {
        Ok(std::fs::read_dir("/proc")?
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
            .collect())
    }

    fn open(&self, pid: i32) -> io::Result<LiveProcess> {
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
        let dir = open(format!("/proc/{pid}").as_str(), flags, Mode::empty())?;
        Ok(LiveProcess { dir })
    }

    fn identity(&self, process: &LiveProcess) -> io::Result<Identity> {
        let text =
            |name| read_at(&process.dir, name).map(|b| String::from_utf8_lossy(&b).into_owned());
        let sid = linux_session_of(&text("stat")?);
        let ids = ids_of(&text("status")?);
        match (sid, ids) {
            (Some(sid), Some((uid, gid))) => Ok(Identity { sid, uid, gid }),
            _ => Err(io::Error::other("unreadable stat or status")),
        }
    }

    fn as_reader<T: Send>(
        &self,
        uid: u32,
        gid: u32,
        read: impl FnOnce() -> T + Send,
    ) -> io::Result<T> {
        let own = (
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        );
        if (uid, gid) == own {
            return Ok(read());
        }
        sealant_process::identity::as_proc_reader(uid, gid, read)
    }

    fn socket_inodes(&self, process: &LiveProcess) -> io::Result<Vec<u64>> {
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
        let mut fds = Dir::from_fd(openat(&process.dir, "fd", flags, Mode::empty())?)?;
        let names: Vec<_> = fds
            .iter()
            .flatten()
            .map(|entry| entry.file_name().to_owned())
            .filter(|name| !matches!(name.to_bytes(), b"." | b".."))
            .collect();
        Ok(names
            .iter()
            .filter_map(|name| readlinkat(&fds, name.as_c_str()).ok())
            .filter_map(|target| {
                target
                    .to_str()?
                    .strip_prefix("socket:[")?
                    .strip_suffix(']')?
                    .parse()
                    .ok()
            })
            .collect())
    }

    fn environ(&self, process: &LiveProcess) -> io::Result<Vec<u8>> {
        read_at(&process.dir, "environ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const LEADER: i32 = 100;
    const UID: u32 = 1000;
    const GID: u32 = 1000;
    const MARKER: &str = "7f3a9c0e5b1d4f2a8c6e0b9d3f5a7c1e";
    const SESSION_ID: &str = "sess_tok_a";

    fn hex_addr(addr: SocketAddr) -> String {
        let hex = match addr.ip() {
            IpAddr::V4(v4) => format!("{:08X}", u32::from_ne_bytes(v4.octets())),
            IpAddr::V6(v6) => v6
                .octets()
                .chunks(4)
                .map(|w| format!("{:08X}", u32::from_ne_bytes([w[0], w[1], w[2], w[3]])))
                .collect(),
        };
        format!("{hex}:{:04X}", addr.port())
    }

    fn row(local: SocketAddr, remote: SocketAddr, state: &str, uid: u32, inode: u64) -> String {
        format!(
            "   0: {} {} {state} 00000000:00000000 00:00000000 00000000  {uid}        0 {inode} 1 0000000000000000 20 4 30 10 -1",
            hex_addr(local),
            hex_addr(remote)
        )
    }

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    #[derive(Clone, Default)]
    struct Proc {
        sid: i32,
        uid: u32,
        gid: u32,
        sockets: Option<Vec<u64>>,
        environ: Option<Vec<u8>>,
        gone: bool,
    }

    #[derive(Default)]
    struct FakeProcFs {
        tcp: Vec<String>,
        tcp6: Vec<String>,
        procs: HashMap<i32, Proc>,
        /// Looks that see the connection still in the accept queue, before it is accepted.
        queued_looks: Mutex<u32>,
        read_delay: Duration,
        readers: Mutex<Vec<(u32, u32)>>,
        fd_reads: Mutex<Vec<i32>>,
    }

    impl ProcFs for FakeProcFs {
        type Process = i32;
        fn tcp_table(&self, v6: bool) -> io::Result<String> {
            let rows = if v6 {
                self.tcp6.clone()
            } else {
                let mut queued = self.queued_looks.lock().unwrap();
                if *queued > 0 {
                    *queued -= 1;
                    vec![row(CONN.peer, CONN.local, "01", UID, 0)]
                } else {
                    self.tcp.clone()
                }
            };
            Ok(std::iter::once(HEADER.to_owned())
                .chain(rows)
                .collect::<Vec<_>>()
                .join("\n"))
        }
        fn pids(&self) -> io::Result<Vec<i32>> {
            let mut pids: Vec<i32> = self.procs.keys().copied().collect();
            pids.sort_unstable();
            Ok(pids)
        }
        fn open(&self, pid: i32) -> io::Result<i32> {
            self.procs
                .get(&pid)
                .map(|_| pid)
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }
        fn identity(&self, pid: &i32) -> io::Result<Identity> {
            let p = &self.procs[pid];
            Ok(Identity {
                sid: p.sid,
                uid: p.uid,
                gid: p.gid,
            })
        }
        fn as_reader<T: Send>(
            &self,
            uid: u32,
            gid: u32,
            read: impl FnOnce() -> T + Send,
        ) -> io::Result<T> {
            self.readers.lock().unwrap().push((uid, gid));
            Ok(read())
        }
        fn socket_inodes(&self, pid: &i32) -> io::Result<Vec<u64>> {
            self.fd_reads.lock().unwrap().push(*pid);
            std::thread::sleep(self.read_delay);
            let p = &self.procs[pid];
            if p.gone {
                return Err(io::Error::from_raw_os_error(
                    nix::errno::Errno::ESRCH as i32,
                ));
            }
            p.sockets
                .clone()
                .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
        }
        fn environ(&self, pid: &i32) -> io::Result<Vec<u8>> {
            self.procs[pid]
                .environ
                .clone()
                .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
        }
    }

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    const CONN: Connection = Connection {
        local: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41000),
        peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000),
    };

    const LISTENING: u64 = 75;
    const SEALANTDS_END: u64 = 76;
    const ACCEPTED: u64 = 77;

    fn accepted() -> FakeProcFs {
        FakeProcFs {
            tcp: vec![
                row(
                    v4(3000),
                    SocketAddr::from(([0, 0, 0, 0], 0)),
                    "0A",
                    UID,
                    LISTENING,
                ),
                row(CONN.local, CONN.peer, "01", 0, SEALANTDS_END),
                row(CONN.peer, CONN.local, "01", UID, ACCEPTED),
            ],
            ..FakeProcFs::default()
        }
    }

    fn environ(entries: &[&str]) -> Option<Vec<u8>> {
        Some(entries.join("\0").into_bytes())
    }

    /// A process of the session's user that holds the accepted socket.
    fn holder(sid: i32, env: &[&str]) -> Proc {
        Proc {
            sid,
            uid: UID,
            gid: GID,
            sockets: Some(vec![3, LISTENING, ACCEPTED]),
            environ: environ(env),
            gone: false,
        }
    }

    fn marked() -> String {
        format!("{SESSION_ENV}={MARKER}")
    }

    fn check_by(fs: &FakeProcFs, deadline: Instant) -> Result<(), ForwardBindingRefusal> {
        let owner = Owner {
            leader_pid: LEADER,
            uid: UID,
            gid: GID,
            marker: MARKER,
        };
        verify(fs, CONN, owner, deadline)
    }

    fn check(fs: &FakeProcFs) -> Result<(), ForwardBindingRefusal> {
        check_by(fs, Instant::now() + Duration::from_secs(5))
    }

    #[test]
    fn a_holder_in_the_leaders_linux_session_is_the_owner() {
        let mut fs = accepted();
        fs.procs.insert(LEADER, holder(LEADER, &["PATH=/bin"]));
        assert_eq!(check(&fs), Ok(()));
    }

    #[test]
    fn a_holder_that_left_the_session_but_carries_its_marker_is_the_owner() {
        let mut fs = accepted();
        fs.procs.insert(200, holder(200, &["PATH=/bin", &marked()]));
        assert_eq!(check(&fs), Ok(()));
    }

    #[test]
    fn the_marker_counts_only_for_the_leaders_user_and_group() {
        for (uid, gid) in [(UID + 1, GID), (UID, GID + 1)] {
            let mut fs = accepted();
            for row in &mut fs.tcp {
                *row = row.replace(&format!("  {UID}  "), &format!("  {uid}  "));
            }
            fs.procs.insert(
                200,
                Proc {
                    uid,
                    gid,
                    ..holder(200, &[&marked()])
                },
            );
            assert_eq!(
                check(&fs),
                Err(ForwardBindingRefusal::PeerMismatch),
                "{uid}:{gid}"
            );
        }
    }

    #[test]
    fn the_public_session_id_is_not_the_marker() {
        let mut fs = accepted();
        let public = format!("{SESSION_ENV}={SESSION_ID}");
        fs.procs.insert(200, holder(200, &[&public]));
        assert_eq!(check(&fs), Err(ForwardBindingRefusal::PeerMismatch));
    }

    #[test]
    fn only_the_first_marker_entry_counts() {
        let mut fs = accepted();
        let forged = format!("{SESSION_ENV}=sess_tok_0");
        fs.procs.insert(200, holder(200, &[&forged, &marked()]));
        assert_eq!(check(&fs), Err(ForwardBindingRefusal::PeerMismatch));
        assert_eq!(
            first_marker(format!("{SESSION_ENV}_X=a\0{}", marked()).as_bytes()),
            Some(MARKER.as_bytes())
        );
    }

    #[test]
    fn a_member_holding_the_socket_does_not_hide_a_foreign_holder() {
        let mut fs = accepted();
        fs.procs.insert(LEADER, holder(LEADER, &[]));
        fs.procs.insert(300, holder(300, &["PATH=/bin"]));
        assert_eq!(check(&fs), Err(ForwardBindingRefusal::PeerMismatch));
    }

    #[test]
    fn an_unreadable_fd_table_never_counts_as_not_holding() {
        let mut fs = accepted();
        fs.procs.insert(
            300,
            Proc {
                sockets: None,
                ..holder(300, &[])
            },
        );
        let start = Instant::now();
        assert_eq!(check(&fs), Err(ForwardBindingRefusal::Unverifiable));
        assert!(
            start.elapsed() < Duration::from_millis(5),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn an_unreadable_fd_table_does_not_undo_a_members_holding() {
        let mut fs = accepted();
        fs.procs.insert(LEADER, holder(LEADER, &[]));
        fs.procs.insert(
            300,
            Proc {
                sockets: None,
                ..holder(300, &[])
            },
        );
        assert_eq!(check(&fs), Ok(()));
    }

    #[test]
    fn a_holder_whose_environment_is_unreadable_is_unverifiable() {
        let mut fs = accepted();
        fs.procs.insert(
            300,
            Proc {
                environ: None,
                ..holder(300, &[])
            },
        );
        assert_eq!(check(&fs), Err(ForwardBindingRefusal::Unverifiable));
    }

    #[test]
    fn a_process_gone_before_its_fds_are_read_holds_nothing() {
        let mut fs = accepted();
        fs.procs.insert(LEADER, holder(LEADER, &[]));
        fs.procs.insert(
            300,
            Proc {
                gone: true,
                ..holder(300, &[])
            },
        );
        assert_eq!(check(&fs), Ok(()));
    }

    #[test]
    fn an_accepted_socket_with_no_holder_in_view_is_refused_at_once() {
        let mut fs = accepted();
        fs.procs.insert(
            LEADER,
            Proc {
                sockets: Some(vec![]),
                ..holder(LEADER, &[])
            },
        );
        let start = Instant::now();
        assert_eq!(check(&fs), Err(ForwardBindingRefusal::Unverifiable));
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn a_connection_never_accepted_is_unverifiable_at_the_deadline() {
        let mut fs = accepted();
        fs.tcp[2] = row(CONN.peer, CONN.local, "01", UID, 0);
        fs.procs.insert(LEADER, holder(LEADER, &[]));
        let deadline = Instant::now() + Duration::from_millis(60);
        assert_eq!(
            check_by(&fs, deadline),
            Err(ForwardBindingRefusal::Unverifiable)
        );
        assert!(Instant::now() <= deadline + Duration::from_millis(20));
    }

    #[test]
    fn the_first_looks_again_come_within_milliseconds() {
        let mut fs = accepted();
        fs.procs.insert(LEADER, holder(LEADER, &[]));
        *fs.queued_looks.lock().unwrap() = 2;
        let start = Instant::now();
        assert_eq!(check(&fs), Ok(()));
        assert!(
            start.elapsed() < Duration::from_millis(15),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn the_deadline_bounds_the_scan_itself() {
        let mut fs = accepted();
        for pid in 1..=10 {
            fs.procs.insert(pid, holder(LEADER, &[]));
        }
        fs.read_delay = Duration::from_millis(30);
        let start = Instant::now();
        let verdict = check_by(&fs, start + Duration::from_millis(100));
        assert_eq!(verdict, Err(ForwardBindingRefusal::Unverifiable));
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn only_the_sockets_uid_is_read_with_one_reader_per_group() {
        let mut fs = accepted();
        fs.procs.insert(LEADER, holder(LEADER, &[]));
        fs.procs.insert(
            101,
            Proc {
                gid: GID + 5,
                sockets: Some(vec![]),
                ..holder(LEADER, &[])
            },
        );
        fs.procs.insert(
            102,
            Proc {
                sockets: Some(vec![]),
                ..holder(LEADER, &[])
            },
        );
        fs.procs.insert(
            900,
            Proc {
                uid: 0,
                gid: 0,
                ..holder(1, &[])
            },
        );
        assert_eq!(check(&fs), Ok(()));
        assert_eq!(
            *fs.readers.lock().unwrap(),
            vec![(UID, GID), (UID, GID + 5)]
        );
        assert!(!fs.fd_reads.lock().unwrap().contains(&900));
    }

    #[test]
    fn the_listening_socket_alone_proves_nothing() {
        let mut fs = accepted();
        fs.tcp.truncate(2);
        fs.procs.insert(LEADER, holder(LEADER, &[]));
        let deadline = Instant::now() + Duration::from_millis(30);
        assert_eq!(
            check_by(&fs, deadline),
            Err(ForwardBindingRefusal::Unverifiable)
        );
    }

    #[test]
    fn a_dual_stack_listener_shows_the_connection_in_tcp6() {
        let mapped = |addr: SocketAddr| match addr.ip() {
            IpAddr::V4(ip) => SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port()),
            IpAddr::V6(_) => addr,
        };
        let mut fs = FakeProcFs {
            tcp6: vec![row(
                mapped(CONN.peer),
                mapped(CONN.local),
                "01",
                UID,
                ACCEPTED,
            )],
            ..FakeProcFs::default()
        };
        fs.procs.insert(LEADER, holder(LEADER, &[]));
        assert_eq!(check(&fs), Ok(()));
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn a_proc_row_parses_as_the_kernel_prints_it() {
        let line = format!(
            "{HEADER}\n   1: 0100007F:0BB8 0100007F:A028 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 20 4 30 10 -1\n   2: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 99 1 0000000000000000 100 0 0 10 0"
        );
        let entries = parse_tcp_table(&line);
        assert_eq!(entries[0].local, v4(3000));
        assert_eq!(entries[0].remote, v4(41000));
        assert!(entries[0].established);
        assert_eq!(entries[0].uid, 1000);
        assert_eq!(entries[0].inode, 4242);
        assert_eq!(
            entries[1].local,
            SocketAddr::from((Ipv6Addr::LOCALHOST, 3000))
        );
        assert!(!entries[1].established);
        assert_eq!(entries[1].uid, 1001);
    }

    #[test]
    fn a_command_name_with_parentheses_keeps_the_session_field() {
        assert_eq!(
            linux_session_of("42 (a) b) (c) S 1 42 4242 0 -1"),
            Some(4242)
        );
    }

    #[test]
    fn status_gives_the_real_ids() {
        let status =
            "Name:\tnode\nUid:\t1000\t1000\t1000\t1000\nGid:\t40970\t40970\t40970\t40970\n";
        assert_eq!(ids_of(status), Some((1000, 40970)));
    }

    #[test]
    fn each_refusal_carries_its_reason() {
        for (refusal, reason) in [
            (ForwardBindingRefusal::OwnerExited, "owner-exited"),
            (ForwardBindingRefusal::PeerMismatch, "peer-mismatch"),
            (ForwardBindingRefusal::Unverifiable, "binding-unverifiable"),
        ] {
            let error = refusal_error(refusal, SESSION_ID);
            assert_eq!(error.detail, Some(serde_json::json!({ "reason": reason })));
        }
    }

    #[test]
    fn a_handle_on_a_process_that_exited_reads_as_gone() {
        use sealant_process::CommandGateExt;
        let child = std::process::Command::new("/bin/sleep")
            .arg("0.2")
            .spawn_gated()
            .expect("spawn");
        let fs = LiveProcFs;
        let process = fs.open(child.pid()).expect("open");
        assert!(fs.identity(&process).is_ok());
        child.wait_with_output().expect("reap");
        let read = fs.identity(&process).expect_err("the process is gone");
        assert!(gone(&read), "{read:?}");
        assert!(fs.socket_inodes(&process).is_err_and(|e| gone(&e)));
    }
}
