//! The guest's filesystem, built by PID 1 before anything else runs (architecture §5.3).
//!
//! The kernel boots with the base disk (`/dev/vda`, read-only) as its root. A normal boot puts
//! an overlay over it, whose upper layer is on the data disk (`/dev/vdb`), and pivots into it, so
//! `apt-get`, `npm i -g` and `/etc` edits work and survive a reboot; the workspace, `/home` and
//! Docker's storage are the data disk's own `ext4`, bind-mounted past the overlay. A recovery
//! boot never looks at the overlay's upper layer — an agent may have wrecked `/` in it — and
//! runs on the clean base disk with the workspace and `/home` bound in.
//!
//! The layout is a list of [`Step`]s ([`normal`], [`recovery`]) so what each boot mounts can be
//! read and tested without root; [`apply`] carries them out.

use std::path::{Path, PathBuf};

/// The read-only base disk.
pub const BASE_DEVICE: &str = "/dev/vda";
/// The writable data disk.
pub const DATA_DEVICE: &str = "/dev/vdb";
/// Where the base disk is mounted for the overlay's lower layer.
pub const BASE_MOUNT: &str = "/mnt/base";
/// Where the data disk is mounted.
pub const DATA_MOUNT: &str = "/mnt/data";
/// Where the overlay root is assembled before the pivot.
pub const NEW_ROOT: &str = "/mnt/newroot";
/// The directories of the data disk a boot needs.
pub const DATA_DIRS: [&str; 5] = ["root-upper", "root-work", "workspace", "home", "docker"];

/// One thing PID 1 does to the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Mount `source` (`fstype`) on `target` unless `target` is a mount point already.
    Mount {
        /// The device or pseudo source.
        source: String,
        /// Where.
        target: PathBuf,
        /// The filesystem type.
        fstype: String,
        /// Mount flags.
        flags: Flags,
        /// Filesystem options (`-o`).
        data: Option<String>,
    },
    /// `mkdir -p`.
    Mkdir(PathBuf),
    /// Bind `from` onto `to` (`to` created if missing).
    Bind {
        /// The source directory.
        from: PathBuf,
        /// The mount point.
        to: PathBuf,
    },
    /// Move the mount at `from` to `to` (`to` created if missing).
    Move {
        /// The mount point now.
        from: PathBuf,
        /// Where it goes.
        to: PathBuf,
    },
    /// `ln -s target link`, unless `link` already exists.
    Symlink {
        /// What the link points at.
        target: PathBuf,
        /// The link.
        link: PathBuf,
    },
    /// Make `new_root` the root (`pivot_root(".", ".")` from inside it) and detach the old one.
    PivotRoot(PathBuf),
}

/// The mount flags a step uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    /// `MS_RDONLY`.
    pub read_only: bool,
    /// `MS_NOSUID`.
    pub nosuid: bool,
    /// `MS_NODEV`.
    pub nodev: bool,
    /// `MS_NOEXEC`.
    pub noexec: bool,
}

const PSEUDO: Flags = Flags {
    read_only: false,
    nosuid: true,
    nodev: true,
    noexec: true,
};

fn mount(source: &str, target: &str, fstype: &str, flags: Flags, data: Option<&str>) -> Step {
    Step::Mount {
        source: source.to_owned(),
        target: PathBuf::from(target),
        fstype: fstype.to_owned(),
        flags,
        data: data.map(str::to_owned),
    }
}

fn symlink(target: &str, link: &str) -> Step {
    Step::Symlink {
        target: PathBuf::from(target),
        link: PathBuf::from(link),
    }
}

/// The kernel and runtime filesystems every boot mounts first, idempotently.
#[must_use]
pub fn early() -> Vec<Step> {
    vec![
        mount("proc", "/proc", "proc", PSEUDO, None),
        mount("sysfs", "/sys", "sysfs", PSEUDO, None),
        mount(
            "devtmpfs",
            "/dev",
            "devtmpfs",
            Flags {
                nosuid: true,
                ..Flags::default()
            },
            Some("mode=0755"),
        ),
        // What devtmpfs does not make and programs expect: the descriptor links (bash process
        // substitution, `/dev/stdin`) and a shared-memory tmpfs (POSIX semaphores, Chromium).
        symlink("/proc/self/fd", "/dev/fd"),
        symlink("/proc/self/fd/0", "/dev/stdin"),
        symlink("/proc/self/fd/1", "/dev/stdout"),
        symlink("/proc/self/fd/2", "/dev/stderr"),
        Step::Mkdir(PathBuf::from("/dev/shm")),
        mount(
            "tmpfs",
            "/dev/shm",
            "tmpfs",
            Flags {
                nosuid: true,
                nodev: true,
                ..Flags::default()
            },
            Some("mode=1777"),
        ),
        Step::Mkdir(PathBuf::from("/dev/pts")),
        mount(
            "devpts",
            "/dev/pts",
            "devpts",
            Flags {
                nosuid: true,
                noexec: true,
                ..Flags::default()
            },
            Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
        ),
        mount(
            "tmpfs",
            "/run",
            "tmpfs",
            Flags {
                nosuid: true,
                nodev: true,
                ..Flags::default()
            },
            Some("mode=0755"),
        ),
        mount(
            "tmpfs",
            "/tmp",
            "tmpfs",
            Flags {
                nosuid: true,
                nodev: true,
                ..Flags::default()
            },
            Some("mode=1777"),
        ),
        mount("cgroup2", "/sys/fs/cgroup", "cgroup2", PSEUDO, None),
        // The base disk is read-only, so the mount points below cannot be made on it: a tmpfs
        // on `/mnt` holds them.
        mount(
            "tmpfs",
            "/mnt",
            "tmpfs",
            Flags {
                nosuid: true,
                nodev: true,
                ..Flags::default()
            },
            Some("mode=0755"),
        ),
    ]
}

fn data_disk() -> Step {
    mount(
        DATA_DEVICE,
        DATA_MOUNT,
        "ext4",
        Flags::default(),
        Some("discard"),
    )
}

fn data(dir: &str) -> PathBuf {
    Path::new(DATA_MOUNT).join(dir)
}

/// A normal boot: the overlay root over the base disk, the data disk's directories bound past
/// it, every runtime filesystem carried across the pivot.
#[must_use]
pub fn normal() -> Vec<Step> {
    let mut steps = early();
    steps.push(Step::Mkdir(PathBuf::from(BASE_MOUNT)));
    steps.push(mount(
        BASE_DEVICE,
        BASE_MOUNT,
        "ext4",
        Flags {
            read_only: true,
            ..Flags::default()
        },
        None,
    ));
    steps.push(Step::Mkdir(PathBuf::from(DATA_MOUNT)));
    steps.push(data_disk());
    steps.extend(DATA_DIRS.iter().map(|dir| Step::Mkdir(data(dir))));
    steps.push(Step::Mkdir(PathBuf::from(NEW_ROOT)));
    steps.push(mount(
        "overlay",
        NEW_ROOT,
        "overlay",
        Flags::default(),
        Some(&format!(
            "lowerdir={BASE_MOUNT},upperdir={DATA_MOUNT}/root-upper,workdir={DATA_MOUNT}/root-work"
        )),
    ));
    let new = |path: &str| Path::new(NEW_ROOT).join(path.trim_start_matches('/'));
    // Carried into the new root, innermost first so each parent moves with its children
    // already gone from under it: `/dev/pts` and `/sys/fs/cgroup` travel with their parents.
    for path in ["/proc", "/sys", "/dev", "/run", "/tmp"] {
        steps.push(Step::Move {
            from: PathBuf::from(path),
            to: new(path),
        });
    }
    steps.push(Step::Move {
        from: PathBuf::from(DATA_MOUNT),
        to: new(DATA_MOUNT),
    });
    steps.push(Step::PivotRoot(PathBuf::from(NEW_ROOT)));
    // After the pivot: the data disk's own ext4, past the overlay.
    for (dir, to) in [
        ("workspace", "/workspace"),
        ("home", "/home"),
        ("docker", "/var/lib/docker"),
    ] {
        steps.push(Step::Bind {
            from: data(dir),
            to: PathBuf::from(to),
        });
    }
    steps
}

/// A recovery boot: the clean base disk as it is, the data disk mounted, the workspace and
/// `/home` bound in. Never the overlay's upper layer, never Docker's storage.
#[must_use]
pub fn recovery() -> Vec<Step> {
    let mut steps = early();
    steps.push(Step::Mkdir(PathBuf::from(DATA_MOUNT)));
    steps.push(data_disk());
    for dir in ["workspace", "home"] {
        steps.push(Step::Mkdir(data(dir)));
    }
    for (dir, to) in [("workspace", "/workspace"), ("home", "/home")] {
        steps.push(Step::Bind {
            from: data(dir),
            to: PathBuf::from(to),
        });
    }
    steps
}

/// Why the layout could not be built.
#[derive(Debug, thiserror::Error)]
#[error("{what} {path}: {source}")]
pub struct LayoutError {
    what: &'static str,
    path: String,
    #[source]
    source: std::io::Error,
}

impl LayoutError {
    fn new(what: &'static str, path: &Path, source: impl Into<std::io::Error>) -> Self {
        Self {
            what,
            path: path.display().to_string(),
            source: source.into(),
        }
    }
}

/// Whether `path` is a mount point: its device differs from its parent's, or it is `/`.
#[must_use]
pub fn is_mount_point(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(here) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(parent) = std::fs::metadata(path.join("..")) else {
        return false;
    };
    here.dev() != parent.dev() || here.ino() == parent.ino()
}

/// Carry out `steps`, in order.
///
/// # Errors
/// The first step that failed.
#[cfg(target_os = "linux")]
pub fn apply(steps: &[Step]) -> Result<(), LayoutError> {
    use nix::mount::{MntFlags, MsFlags, mount as sys_mount, umount2};

    let ms = |flags: Flags| {
        let mut out = MsFlags::empty();
        out.set(MsFlags::MS_RDONLY, flags.read_only);
        out.set(MsFlags::MS_NOSUID, flags.nosuid);
        out.set(MsFlags::MS_NODEV, flags.nodev);
        out.set(MsFlags::MS_NOEXEC, flags.noexec);
        out
    };
    let mkdir =
        |path: &Path| std::fs::create_dir_all(path).map_err(|e| LayoutError::new("mkdir", path, e));
    for step in steps {
        match step {
            Step::Mount {
                source,
                target,
                fstype,
                flags,
                data,
            } => {
                if is_mount_point(target) {
                    tracing::debug!(target = %target.display(), "already mounted");
                    continue;
                }
                sys_mount(
                    Some(source.as_str()),
                    target.as_path(),
                    Some(fstype.as_str()),
                    ms(*flags),
                    data.as_deref(),
                )
                .map_err(|e| LayoutError::new("mount", target, e))?;
            }
            Step::Mkdir(path) => mkdir(path)?,
            Step::Bind { from, to } => {
                mkdir(to)?;
                sys_mount(
                    Some(from.as_path()),
                    to.as_path(),
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )
                .map_err(|e| LayoutError::new("bind", to, e))?;
            }
            Step::Move { from, to } => {
                if !is_mount_point(from) {
                    continue;
                }
                mkdir(to)?;
                sys_mount(
                    Some(from.as_path()),
                    to.as_path(),
                    None::<&str>,
                    MsFlags::MS_MOVE,
                    None::<&str>,
                )
                .map_err(|e| LayoutError::new("move", to, e))?;
            }
            Step::Symlink { target, link } => {
                if std::fs::symlink_metadata(link).is_ok() {
                    continue;
                }
                std::os::unix::fs::symlink(target, link)
                    .map_err(|e| LayoutError::new("symlink", link, e))?;
            }
            Step::PivotRoot(new_root) => {
                std::env::set_current_dir(new_root)
                    .map_err(|e| LayoutError::new("chdir", new_root, e))?;
                nix::unistd::pivot_root(".", ".")
                    .map_err(|e| LayoutError::new("pivot_root", new_root, e))?;
                // The old root is now stacked under the new one at `/`: detach it.
                umount2(".", MntFlags::MNT_DETACH)
                    .map_err(|e| LayoutError::new("detach old root", Path::new("/"), e))?;
                std::env::set_current_dir("/")
                    .map_err(|e| LayoutError::new("chdir", Path::new("/"), e))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mounts(steps: &[Step]) -> Vec<(&str, &Path, Option<&str>, Flags)> {
        steps
            .iter()
            .filter_map(|step| match step {
                Step::Mount {
                    source,
                    target,
                    flags,
                    data,
                    ..
                } => Some((source.as_str(), target.as_path(), data.as_deref(), *flags)),
                _ => None,
            })
            .collect()
    }

    fn binds(steps: &[Step]) -> Vec<(&Path, &Path)> {
        steps
            .iter()
            .filter_map(|step| match step {
                Step::Bind { from, to } => Some((from.as_path(), to.as_path())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn every_boot_mounts_the_runtime_filesystems_first() {
        for steps in [normal(), recovery()] {
            let targets: Vec<&Path> = mounts(&steps).iter().map(|m| m.1).collect();
            for path in [
                "/proc",
                "/sys",
                "/dev",
                "/dev/pts",
                "/run",
                "/tmp",
                "/sys/fs/cgroup",
            ] {
                assert!(targets.contains(&Path::new(path)), "{path}");
            }
        }
    }

    #[test]
    fn every_boot_has_shared_memory_and_the_descriptor_links_after_devtmpfs() {
        for steps in [normal(), recovery()] {
            let devtmpfs = steps
                .iter()
                .position(|s| matches!(s, Step::Mount { fstype, .. } if fstype == "devtmpfs"))
                .expect("devtmpfs");
            let at = |wanted: &Step| {
                steps
                    .iter()
                    .position(|s| s == wanted)
                    .unwrap_or_else(|| panic!("{wanted:?} missing"))
            };
            for (target, link) in [
                ("/proc/self/fd", "/dev/fd"),
                ("/proc/self/fd/0", "/dev/stdin"),
                ("/proc/self/fd/1", "/dev/stdout"),
                ("/proc/self/fd/2", "/dev/stderr"),
            ] {
                assert!(at(&symlink(target, link)) > devtmpfs, "{link}");
            }
            let shm = mounts(&steps)
                .into_iter()
                .find(|m| m.1 == Path::new("/dev/shm"))
                .expect("/dev/shm");
            assert_eq!(shm.2, Some("mode=1777"));
            assert!(shm.3.nosuid && shm.3.nodev && !shm.3.read_only);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_symlink_step_is_made_once_and_left_alone_after() {
        let dir = tempfile::tempdir().expect("tempdir");
        let link = dir.path().join("fd");
        let step = Step::Symlink {
            target: PathBuf::from("/proc/self/fd"),
            link: link.clone(),
        };
        apply(std::slice::from_ref(&step)).expect("made");
        apply(std::slice::from_ref(&step)).expect("idempotent");
        assert_eq!(
            std::fs::read_link(&link).expect("link"),
            Path::new("/proc/self/fd")
        );
    }

    #[test]
    fn a_normal_boot_overlays_the_read_only_base_with_the_data_disk_and_pivots() {
        let steps = normal();
        let all = mounts(&steps);
        let base = all.iter().find(|m| m.0 == BASE_DEVICE).expect("base disk");
        assert_eq!(base.1, Path::new(BASE_MOUNT));
        assert!(base.3.read_only);
        let data = all.iter().find(|m| m.0 == DATA_DEVICE).expect("data disk");
        assert_eq!(data.1, Path::new(DATA_MOUNT));
        assert!(!data.3.read_only);
        assert_eq!(data.2, Some("discard"));
        let overlay = all.iter().find(|m| m.0 == "overlay").expect("overlay");
        assert_eq!(overlay.1, Path::new(NEW_ROOT));
        assert_eq!(
            overlay.2,
            Some("lowerdir=/mnt/base,upperdir=/mnt/data/root-upper,workdir=/mnt/data/root-work")
        );
        for dir in DATA_DIRS {
            assert!(
                steps.contains(&Step::Mkdir(Path::new(DATA_MOUNT).join(dir))),
                "{dir}"
            );
        }

        let pivot = steps
            .iter()
            .position(|s| matches!(s, Step::PivotRoot(_)))
            .expect("pivot");
        let overlay_at = steps
            .iter()
            .position(|s| matches!(s, Step::Mount { source, .. } if source == "overlay"))
            .expect("overlay step");
        assert!(overlay_at < pivot);
        // The data disk and the runtime filesystems cross into the new root before the pivot.
        for path in ["/proc", "/sys", "/dev", "/run", "/tmp", DATA_MOUNT] {
            let moved = steps
                .iter()
                .position(|s| matches!(s, Step::Move { from, .. } if from == Path::new(path)));
            assert!(moved.is_some_and(|at| at < pivot), "{path}");
        }
        // The binds are the data disk's ext4, past the overlay, after the pivot.
        assert_eq!(
            binds(&steps),
            [
                (Path::new("/mnt/data/workspace"), Path::new("/workspace")),
                (Path::new("/mnt/data/home"), Path::new("/home")),
                (Path::new("/mnt/data/docker"), Path::new("/var/lib/docker")),
            ]
        );
        assert!(
            steps
                .iter()
                .skip(pivot)
                .filter(|s| matches!(s, Step::Bind { .. }))
                .count()
                == 3
        );
    }

    #[test]
    fn a_recovery_boot_never_touches_the_overlay_or_dockers_storage() {
        let steps = recovery();
        let text = format!("{steps:?}");
        for word in ["root-upper", "root-work", "overlay", "docker", BASE_DEVICE] {
            assert!(!text.contains(word), "{word} in {text}");
        }
        assert!(!steps.iter().any(|s| matches!(s, Step::PivotRoot(_))));
        assert_eq!(
            binds(&steps),
            [
                (Path::new("/mnt/data/workspace"), Path::new("/workspace")),
                (Path::new("/mnt/data/home"), Path::new("/home")),
            ]
        );
        let data = mounts(&steps)
            .into_iter()
            .find(|m| m.0 == DATA_DEVICE)
            .expect("data disk");
        assert_eq!(data.1, Path::new(DATA_MOUNT));
    }

    #[test]
    fn a_mount_point_is_told_from_a_plain_directory() {
        assert!(is_mount_point(Path::new("/")));
        assert!(is_mount_point(Path::new("/proc")));
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!is_mount_point(dir.path()));
        assert!(!is_mount_point(&dir.path().join("absent")));
    }
}
