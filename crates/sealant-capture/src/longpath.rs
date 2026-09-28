//! Filesystem calls for paths of any length.
//!
//! A path is bytes, and nothing bounds how long one gets: a directory tree 17 levels deep with
//! 243-byte names is a 4,186-byte path, and a file below it holds work product like any other.
//! The kernel refuses a path of `PATH_MAX` (4,096) bytes or more in a single call
//! (`ENAMETOOLONG`), so `std::fs` and `walkdir` cannot reach it: before these calls, one such path
//! failed the worktree metadata overlay, and with it every snap of the session.
//!
//! Each call here takes a path of any length. A path that fits goes to `std::fs` as it is; a
//! longer one is resolved a piece at a time: its parent directory is opened through `openat`
//! in runs of whole components that each fit, and the call is made relative to that directory
//! (`fstatat` through an `O_PATH` descriptor, `readlinkat`, `openat`, `mkdirat`, `unlinkat`,
//! `renameat`, `linkat`, `symlinkat`, `fchmodat`, `utimensat`). Symlinks in the parent are
//! followed as the kernel would follow them in one call; the last component is followed or not
//! as the `std::fs` call of the same name does.
//!
//! [`walk`] lists a tree through [`read_dir`], so a walk never stops at the length limit either.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use nix::dir::{Dir, Type};
use nix::fcntl::{AT_FDCWD, AtFlags, OFlag, openat, readlinkat, renameat};
use nix::sys::stat::{FchmodatFlags, Mode, UtimensatFlags, fchmodat, mkdirat, utimensat};
use nix::sys::time::TimeSpec;
use nix::unistd::{UnlinkatFlags, linkat, symlinkat, unlinkat};

/// Linux's `PATH_MAX`: the bytes one path argument may take, its terminating NUL included. A
/// path of this many bytes or more is resolved a piece at a time.
pub const PATH_MAX: usize = 4096;

/// Whether `path` fits in one system call.
#[must_use]
pub fn fits(path: &Path) -> bool {
    path.as_os_str().len() < PATH_MAX
}

fn nix_err(e: nix::errno::Errno) -> io::Error {
    io::Error::from(e)
}

#[cfg(test)]
thread_local! {
    /// Paths whose `symlink_metadata` and `read_dir` fail on this thread, with the errno.
    static FAULTS: std::cell::RefCell<Vec<(PathBuf, i32)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Make `symlink_metadata` and `read_dir` of `path` fail with `errno` on this thread (tests).
#[cfg(test)]
pub(crate) fn inject_fault(path: &Path, errno: i32) {
    FAULTS.with(|f| f.borrow_mut().push((path.to_path_buf(), errno)));
}

/// The injected failure for `path`, if any.
fn fault(path: &Path) -> Option<io::Error> {
    #[cfg(test)]
    {
        FAULTS.with(|f| {
            f.borrow()
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, errno)| io::Error::from_raw_os_error(*errno))
        })
    }
    #[cfg(not(test))]
    {
        let _ = path;
        None
    }
}

/// The directory a call is made relative to: the working directory (a path that fits, or a
/// relative parent of one), or an opened directory.
enum Base {
    Cwd,
    Fd(OwnedFd),
}

impl Base {
    fn fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Cwd => AT_FDCWD,
            Self::Fd(fd) => fd.as_fd(),
        }
    }
}

/// A long path as its opened parent directory and its last component.
struct At {
    dir: Base,
    name: OsString,
}

/// Open the directory `dir` (bytes; absolute or relative) with `flags`, a run of whole
/// components at a time, each run shorter than [`PATH_MAX`].
fn open_dir(dir: &[u8], flags: OFlag) -> io::Result<Base> {
    let mut base = Base::Cwd;
    let mut rest = dir;
    if rest.is_empty() {
        rest = b".";
    }
    loop {
        let (run, next): (&[u8], &[u8]) = if rest.len() < PATH_MAX {
            (rest, b"")
        } else {
            // The longest run of whole components that fits.
            let window = &rest[..PATH_MAX - 1];
            match window.iter().rposition(|b| *b == b'/') {
                Some(0) => (b"/", &rest[1..]),
                Some(i) => (&rest[..i], &rest[i + 1..]),
                // One component longer than PATH_MAX: no filesystem holds one (NAME_MAX).
                None => return Err(io::Error::from_raw_os_error(nix::libc::ENAMETOOLONG)),
            }
        };
        let fd = openat(
            base.fd(),
            OsStr::from_bytes(run),
            flags | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(nix_err)?;
        base = Base::Fd(fd);
        // What is left is relative to the directory just opened.
        let trimmed = next
            .iter()
            .position(|b| *b != b'/')
            .map_or(&b""[..], |i| &next[i..]);
        if trimmed.is_empty() {
            return Ok(base);
        }
        rest = trimmed;
    }
}

/// `path` as its parent directory, opened, and its last component. Only for a path that does
/// not fit: it has a `/` (a single component is at most `NAME_MAX` bytes).
fn at(path: &Path) -> io::Result<At> {
    let bytes = path.as_os_str().as_bytes();
    let end = bytes.iter().rposition(|b| *b != b'/').map_or(0, |i| i + 1);
    let bytes = &bytes[..end];
    let (parent, name) = match bytes.iter().rposition(|b| *b == b'/') {
        Some(0) => (&b"/"[..], &bytes[1..]),
        Some(i) => (&bytes[..i], &bytes[i + 1..]),
        None => (&b"."[..], bytes),
    };
    if name.is_empty() {
        return Err(io::Error::from_raw_os_error(nix::libc::ENAMETOOLONG));
    }
    Ok(At {
        dir: open_dir(parent, OFlag::O_PATH)?,
        name: OsStr::from_bytes(name).to_owned(),
    })
}

fn open_at(path: &Path, flags: OFlag, mode: u32) -> io::Result<File> {
    let at = at(path)?;
    let fd = openat(
        at.dir.fd(),
        at.name.as_os_str(),
        flags | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(mode),
    )
    .map_err(nix_err)?;
    Ok(File::from(fd))
}

/// Open the directory at `path`, of any length, as an `O_PATH` descriptor (a symlink at its last
/// component not followed): `/proc/self/fd/<fd>` then names it, in a few bytes, to a call that
/// takes only a path (`inotify_add_watch`).
pub fn open_dir_path(path: &Path) -> io::Result<OwnedFd> {
    let at = at(path)?;
    openat(
        at.dir.fd(),
        at.name.as_os_str(),
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(nix_err)
}

/// `fs::symlink_metadata`: the path itself, a symlink not followed.
pub fn symlink_metadata(path: &Path) -> io::Result<Metadata> {
    if let Some(e) = fault(path) {
        return Err(e);
    }
    if fits(path) {
        return fs::symlink_metadata(path);
    }
    open_at(path, OFlag::O_PATH | OFlag::O_NOFOLLOW, 0)?.metadata()
}

/// `fs::metadata`: a symlink followed.
pub fn metadata(path: &Path) -> io::Result<Metadata> {
    if fits(path) {
        return fs::metadata(path);
    }
    open_at(path, OFlag::O_PATH, 0)?.metadata()
}

/// Whether anything is at `path` (a dangling symlink counts).
#[must_use]
pub fn exists(path: &Path) -> bool {
    symlink_metadata(path).is_ok()
}

/// `fs::read_link`.
pub fn read_link(path: &Path) -> io::Result<PathBuf> {
    if fits(path) {
        return fs::read_link(path);
    }
    let at = at(path)?;
    readlinkat(at.dir.fd(), at.name.as_os_str())
        .map(PathBuf::from)
        .map_err(nix_err)
}

/// `File::open`: read only.
pub fn open(path: &Path) -> io::Result<File> {
    if fits(path) {
        return File::open(path);
    }
    open_at(path, OFlag::O_RDONLY, 0)
}

/// `File::create`: write only, created (`0o666` under the umask) or truncated.
pub fn create(path: &Path) -> io::Result<File> {
    if fits(path) {
        return File::create(path);
    }
    open_at(
        path,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_TRUNC,
        0o666,
    )
}

/// What a directory entry is, as the listing says (`None` when the filesystem does not say).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A directory.
    Dir,
    /// A regular file.
    File,
    /// A symlink.
    Symlink,
    /// A socket, fifo or device.
    Other,
}

impl Kind {
    /// The kind of `meta` (not following a symlink).
    #[must_use]
    pub fn of(meta: &Metadata) -> Self {
        let ft = meta.file_type();
        if ft.is_symlink() {
            Self::Symlink
        } else if ft.is_dir() {
            Self::Dir
        } else if ft.is_file() {
            Self::File
        } else {
            Self::Other
        }
    }

    fn of_type(t: Type) -> Self {
        match t {
            Type::Directory => Self::Dir,
            Type::File => Self::File,
            Type::Symlink => Self::Symlink,
            _ => Self::Other,
        }
    }
}

/// The names in the directory `path` (not `.` and `..`), sorted by their bytes, each with its
/// kind when the listing gives it.
pub fn read_dir(path: &Path) -> io::Result<Vec<(OsString, Option<Kind>)>> {
    if let Some(e) = fault(path) {
        return Err(e);
    }
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
    let mut dir = if fits(path) {
        Dir::open(path, flags, Mode::empty()).map_err(nix_err)?
    } else {
        let at = at(path)?;
        Dir::openat(at.dir.fd(), at.name.as_os_str(), flags, Mode::empty()).map_err(nix_err)?
    };
    let mut names = Vec::new();
    for entry in dir.iter() {
        let entry = entry.map_err(nix_err)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push((
            OsStr::from_bytes(name).to_owned(),
            entry.file_type().map(Kind::of_type),
        ));
    }
    names.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Ok(names)
}

/// `fs::create_dir` (`0o777` under the umask).
pub fn create_dir(path: &Path) -> io::Result<()> {
    if fits(path) {
        return fs::create_dir(path);
    }
    let at = at(path)?;
    mkdirat(
        at.dir.fd(),
        at.name.as_os_str(),
        Mode::from_bits_truncate(0o777),
    )
    .map_err(nix_err)
}

/// `fs::create_dir_all`: every missing directory on the way, a symlink to a directory taken
/// for one.
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    if fits(path) {
        return fs::create_dir_all(path);
    }
    let is_dir = |p: &Path| metadata(p).is_ok_and(|m| m.is_dir());
    // The missing ancestors, deepest first, then created outermost first.
    let mut missing: Vec<&Path> = Vec::new();
    let mut at = Some(path);
    while let Some(p) = at {
        if p.as_os_str().is_empty() || is_dir(p) {
            break;
        }
        missing.push(p);
        at = p.parent();
    }
    for p in missing.into_iter().rev() {
        match create_dir(p) {
            Ok(()) => {}
            Err(_) if is_dir(p) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `fs::remove_file` (a symlink itself, never its target).
pub fn remove_file(path: &Path) -> io::Result<()> {
    if fits(path) {
        return fs::remove_file(path);
    }
    let at = at(path)?;
    unlinkat(at.dir.fd(), at.name.as_os_str(), UnlinkatFlags::NoRemoveDir).map_err(nix_err)
}

/// `fs::remove_dir`: an empty directory.
pub fn remove_dir(path: &Path) -> io::Result<()> {
    if fits(path) {
        return fs::remove_dir(path);
    }
    let at = at(path)?;
    unlinkat(at.dir.fd(), at.name.as_os_str(), UnlinkatFlags::RemoveDir).map_err(nix_err)
}

/// `fs::remove_dir_all`: a directory and everything under it (a symlink inside is removed, never
/// followed).
pub fn remove_dir_all(path: &Path) -> io::Result<()> {
    if fits(path) {
        return fs::remove_dir_all(path);
    }
    for (name, kind) in read_dir(path)? {
        let child = path.join(&name);
        let kind = match kind {
            Some(kind) => kind,
            None => Kind::of(&symlink_metadata(&child)?),
        };
        if kind == Kind::Dir {
            remove_dir_all(&child)?;
        } else {
            remove_file(&child)?;
        }
    }
    remove_dir(path)
}

/// `fs::rename`.
pub fn rename(from: &Path, to: &Path) -> io::Result<()> {
    if fits(from) && fits(to) {
        return fs::rename(from, to);
    }
    let (a, b) = (at(from)?, at(to)?);
    renameat(
        a.dir.fd(),
        a.name.as_os_str(),
        b.dir.fd(),
        b.name.as_os_str(),
    )
    .map_err(nix_err)
}

/// `fs::hard_link`: `link` becomes a name of `original`'s inode (a symlink not followed).
pub fn hard_link(original: &Path, link: &Path) -> io::Result<()> {
    if fits(original) && fits(link) {
        return fs::hard_link(original, link);
    }
    let (a, b) = (at(original)?, at(link)?);
    linkat(
        a.dir.fd(),
        a.name.as_os_str(),
        b.dir.fd(),
        b.name.as_os_str(),
        AtFlags::empty(),
    )
    .map_err(nix_err)
}

/// `std::os::unix::fs::symlink`: a symlink at `link` whose text is `target`.
pub fn symlink(target: &Path, link: &Path) -> io::Result<()> {
    if fits(link) {
        return std::os::unix::fs::symlink(target, link);
    }
    let at = at(link)?;
    symlinkat(target, at.dir.fd(), at.name.as_os_str()).map_err(nix_err)
}

/// `fs::set_permissions` with `mode` (a symlink followed).
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    if fits(path) {
        return fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    let at = at(path)?;
    fchmodat(
        at.dir.fd(),
        at.name.as_os_str(),
        Mode::from_bits_truncate(mode),
        FchmodatFlags::FollowSymlink,
    )
    .map_err(nix_err)
}

/// Set `path`'s mtime (nanoseconds since the epoch) without following a symlink, so a symlink
/// gets its own mtime and a file is not opened (its mode may forbid that).
pub fn set_mtime_nofollow(path: &Path, mtime_ns: i128) -> io::Result<()> {
    let secs = i64::try_from(mtime_ns.div_euclid(1_000_000_000)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{mtime_ns} ns since the epoch is past what a file's time holds"),
        )
    })?;
    // Below 10^9: fits every `c_long`.
    #[allow(clippy::cast_possible_truncation)]
    let nanos = mtime_ns.rem_euclid(1_000_000_000) as i64;
    let mtime = TimeSpec::new(secs, nanos);
    let (base, name): (Base, OsString) = if fits(path) {
        (Base::Cwd, path.as_os_str().to_owned())
    } else {
        let at = at(path)?;
        (at.dir, at.name)
    };
    utimensat(
        base.fd(),
        name.as_os_str(),
        &TimeSpec::UTIME_OMIT,
        &mtime,
        UtimensatFlags::NoFollowSymlink,
    )
    .map_err(nix_err)
}

/// `fs::copy`: `from`'s bytes and permission bits into `to`.
pub fn copy(from: &Path, to: &Path) -> io::Result<u64> {
    if fits(from) && fits(to) {
        return fs::copy(from, to);
    }
    let mut src = open(from)?;
    let mode = src.metadata()?.permissions().mode();
    let mut dst = create(to)?;
    let mut buf = vec![0u8; 1 << 16];
    let mut copied = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])?;
        copied += n as u64;
    }
    dst.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(copied)
}

/// One step of a [`walk`].
#[derive(Debug)]
pub enum Visit<'a> {
    /// An entry below the root (`depth` 1 is a child of the root), with its kind.
    Entry {
        /// Its path (the root joined with the names down to it).
        path: &'a Path,
        /// Components below the root.
        depth: usize,
        /// What it is.
        kind: Kind,
    },
    /// A directory that could not be listed (the root is depth 0), or an entry whose kind the
    /// listing did not give and that could not be stat'ed.
    Error {
        /// Its path.
        path: &'a Path,
        /// Components below the root.
        depth: usize,
        /// What the filesystem said.
        error: io::Error,
    },
}

/// Walk the tree under `root` depth first, each directory's entries in the byte order of their
/// names, a directory before what it holds: `visit` gets every entry and every error, and for a
/// directory returns whether to descend into it. Symlinks are never followed. The root itself
/// is not visited; a root that cannot be listed is one [`Visit::Error`] at depth 0.
pub fn walk(root: &Path, visit: &mut dyn FnMut(Visit<'_>) -> bool) {
    let mut stack: Vec<(PathBuf, usize, Option<Kind>)> = Vec::new();
    let push = |stack: &mut Vec<(PathBuf, usize, Option<Kind>)>,
                dir: &Path,
                depth: usize,
                visit: &mut dyn FnMut(Visit<'_>) -> bool| {
        match read_dir(dir) {
            Ok(names) => {
                for (name, kind) in names.into_iter().rev() {
                    stack.push((dir.join(name), depth + 1, kind));
                }
            }
            Err(error) => {
                visit(Visit::Error {
                    path: dir,
                    depth,
                    error,
                });
            }
        }
    };
    push(&mut stack, root, 0, visit);
    while let Some((path, depth, kind)) = stack.pop() {
        let kind = match kind {
            Some(kind) => kind,
            None => match symlink_metadata(&path) {
                Ok(meta) => Kind::of(&meta),
                Err(error) => {
                    visit(Visit::Error {
                        path: &path,
                        depth,
                        error,
                    });
                    continue;
                }
            },
        };
        let descend = visit(Visit::Entry {
            path: &path,
            depth,
            kind,
        });
        if kind == Kind::Dir && descend {
            push(&mut stack, &path, depth, visit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// A directory chain under `base` whose deepest path is longer than `PATH_MAX`: 18 levels of
    /// 243-byte names.
    fn deep(base: &Path) -> PathBuf {
        let mut p = base.to_path_buf();
        for i in 0..18 {
            p = p.join(format!("d{i:02}{}", "x".repeat(240)));
            create_dir(&p).unwrap();
        }
        assert!(!fits(&p));
        p
    }

    #[test]
    fn every_call_reaches_a_path_longer_than_path_max() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = deep(tmp.path());
        assert!(fs::symlink_metadata(&dir).is_err(), "std cannot reach it");
        let file = dir.join("work.txt");
        create(&file).unwrap().write_all(b"deep work\n").unwrap();
        let mut text = String::new();
        open(&file).unwrap().read_to_string(&mut text).unwrap();
        assert_eq!(text, "deep work\n");
        assert!(symlink_metadata(&file).unwrap().is_file());
        set_mode(&file, 0o640).unwrap();
        assert_eq!(metadata(&file).unwrap().mode() & 0o7777, 0o640);
        set_mtime_nofollow(&file, 1_500_000_000_123_456_789).unwrap();
        assert_eq!(
            crate::index::mtime_ns(&symlink_metadata(&file).unwrap()),
            1_500_000_000_123_456_789
        );
        let link = dir.join("link");
        symlink(Path::new("work.txt"), &link).unwrap();
        assert_eq!(read_link(&link).unwrap(), Path::new("work.txt"));
        assert!(symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert!(metadata(&link).unwrap().is_file());
        let hard = dir.join("hard");
        hard_link(&file, &hard).unwrap();
        assert_eq!(
            symlink_metadata(&hard).unwrap().ino(),
            symlink_metadata(&file).unwrap().ino()
        );
        let nested = dir.join("a/b/c");
        create_dir_all(&nested).unwrap();
        rename(&hard, &nested.join("moved")).unwrap();
        assert!(!exists(&hard));
        copy(&file, &nested.join("copy")).unwrap();
        let names: Vec<OsString> = read_dir(&dir).unwrap().into_iter().map(|e| e.0).collect();
        assert_eq!(names, ["a", "link", "work.txt"]);
        let mut seen = Vec::new();
        walk(tmp.path(), &mut |v| {
            if let Visit::Entry { path, .. } = v {
                seen.push(path.file_name().unwrap().to_owned());
            }
            true
        });
        assert!(seen.iter().any(|n| n == "moved"), "{seen:?}");
        remove_file(&link).unwrap();
        remove_dir_all(&dir.join("a")).unwrap();
        assert!(!exists(&dir.join("a")));
        remove_file(&file).unwrap();
        remove_dir(&dir).unwrap();
        assert!(!exists(&dir));
    }
}
