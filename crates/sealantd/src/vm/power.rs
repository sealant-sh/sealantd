//! The power button, and the data disk left clean for the power-off.
//!
//! Cloud Hypervisor's ACPI power button press reaches the guest as a `KEY_POWER` key event on
//! an evdev device. A press asks for the same graceful shutdown as the runner's shutdown frame
//! ([`super::channel`]), so a host that can only press the button still gets a final flush and
//! a synced disk. Before the power-off the data disk is remounted read-only ([`settle`]).

use std::io::Read as _;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use tokio::sync::mpsc;

/// What [`settle`] made of one mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// Remounted read-only: its journal is written out and the filesystem marked clean.
    ReadOnly,
    /// Not a mount point (the layout never got that far): left alone.
    NotMounted,
    /// Still in use (`EBUSY`: a file open for writing on it), left read-write. It was synced;
    /// the next mount replays its journal, losing nothing.
    Busy,
    /// The remount failed otherwise, and it is left as it is.
    Failed(Errno),
}

/// Remount each of `mounts` read-only, in order, before the power-off (SLNT-1325). `sync`
/// makes the data durable but leaves an ext4 mounted read-write marked as needing recovery, so
/// `e2fsck -fn data.img` after every power-off found a journal to replay. Remounted read-only,
/// ext4 writes its journal out and marks itself clean. A mount `is_mounted` says is not there
/// is passed over; one still busy, or one whose remount fails, is logged and the power-off goes
/// on. What each came to, in order.
pub fn settle(
    mounts: &[&Path],
    is_mounted: impl Fn(&Path) -> bool,
    mut remount: impl FnMut(&Path) -> Result<(), Errno>,
) -> Vec<Settled> {
    mounts
        .iter()
        .map(|path| {
            if !is_mounted(path) {
                return Settled::NotMounted;
            }
            match remount(path) {
                Ok(()) => {
                    tracing::info!(path = %path.display(), "remounted read-only for the power-off");
                    Settled::ReadOnly
                }
                Err(Errno::EBUSY) => {
                    tracing::warn!(
                        path = %path.display(),
                        "still in use, left read-write for the power-off; it was synced, and \
                         its journal replays at the next mount"
                    );
                    Settled::Busy
                }
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "could not remount read-only for the power-off");
                    Settled::Failed(error)
                }
            }
        })
        .collect()
}

/// `mount -o remount,ro <path>`: the filesystem under `path` (its superblock, so every bind
/// of it too) made read-only.
///
/// # Errors
/// The kernel's.
pub fn remount_read_only(path: &Path) -> Result<(), Errno> {
    #[cfg(target_os = "linux")]
    {
        use nix::mount::{MsFlags, mount};
        mount(
            None::<&str>,
            path,
            None::<&str>,
            MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(Errno::ENOSYS)
    }
}

/// `EV_KEY` (`linux/input-event-codes.h`).
const EV_KEY: u16 = 1;
/// `KEY_POWER`.
const KEY_POWER: u16 = 116;
/// `struct input_event` on a 64-bit kernel: a 16-byte `timeval`, `type`, `code`, `value`.
pub const EVENT_SIZE: usize = 24;

/// Whether `events` (whole `input_event` records) hold a `KEY_POWER` press.
#[must_use]
pub fn holds_power_press(events: &[u8]) -> bool {
    events.as_chunks::<EVENT_SIZE>().0.iter().any(|event| {
        let kind = u16::from_ne_bytes([event[16], event[17]]);
        let code = u16::from_ne_bytes([event[18], event[19]]);
        let value = i32::from_ne_bytes([event[20], event[21], event[22], event[23]]);
        kind == EV_KEY && code == KEY_POWER && value == 1
    })
}

/// The evdev devices under `dir` (`event*`).
#[must_use]
pub fn devices(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("event"))
        .map(|entry| entry.path())
        .collect();
    found.sort();
    found
}

/// Watch every evdev device on a thread of its own and send on `ask` at the first power press.
/// A guest without evdev devices logs that and watches nothing.
pub fn spawn(ask: mpsc::Sender<&'static str>) {
    let found = devices(Path::new("/dev/input"));
    if found.is_empty() {
        tracing::info!("no evdev device: the power button is not watched");
        return;
    }
    for device in found {
        let ask = ask.clone();
        // Blocking reads on a device that may never send anything: a plain thread, which the
        // power-off ends.
        let spawned = std::thread::Builder::new()
            .name("power-button".to_owned())
            .spawn(move || watch(&device, &ask));
        if let Err(error) = spawned {
            tracing::warn!(%error, "the power button watcher could not start");
        }
    }
}

fn watch(device: &Path, ask: &mpsc::Sender<&'static str>) {
    let Ok(mut file) = std::fs::File::open(device) else {
        return;
    };
    let mut buf = vec![0u8; EVENT_SIZE * 64];
    loop {
        match file.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(read) if holds_power_press(&buf[..read]) => {
                let _ = ask.blocking_send("the power button");
                return;
            }
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u16, code: u16, value: i32) -> Vec<u8> {
        let mut out = vec![0u8; 16];
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&code.to_ne_bytes());
        out.extend_from_slice(&value.to_ne_bytes());
        out
    }

    #[test]
    fn a_power_press_is_found_among_other_events() {
        let mut events = event(EV_KEY, 30, 1); // KEY_A
        events.extend(event(0, 0, 0)); // EV_SYN
        assert!(!holds_power_press(&events));
        events.extend(event(EV_KEY, KEY_POWER, 1));
        assert!(holds_power_press(&events));
    }

    #[test]
    fn a_power_release_or_repeat_is_not_a_press() {
        assert!(!holds_power_press(&event(EV_KEY, KEY_POWER, 0)));
        assert!(!holds_power_press(&event(EV_KEY, KEY_POWER, 2)));
        // A truncated record is ignored.
        assert!(!holds_power_press(&event(EV_KEY, KEY_POWER, 1)[..20]));
    }

    /// Every mount is tried in order; a busy one, or one that fails otherwise, does not stop
    /// the rest; one that is not mounted is never remounted.
    #[test]
    fn a_busy_or_failed_remount_is_reported_and_the_rest_still_settle() {
        let mut tried: Vec<PathBuf> = Vec::new();
        let settled = settle(
            &[
                Path::new("/"),
                Path::new("/mnt/data"),
                Path::new("/mnt/absent"),
                Path::new("/mnt/other"),
            ],
            |path| path != Path::new("/mnt/absent"),
            |path| {
                tried.push(path.to_path_buf());
                match path.to_str() {
                    Some("/") => Err(Errno::EBUSY),
                    Some("/mnt/other") => Err(Errno::EINVAL),
                    _ => Ok(()),
                }
            },
        );
        assert_eq!(
            settled,
            [
                Settled::Busy,
                Settled::ReadOnly,
                Settled::NotMounted,
                Settled::Failed(Errno::EINVAL),
            ]
        );
        assert_eq!(
            tried,
            [
                PathBuf::from("/"),
                PathBuf::from("/mnt/data"),
                PathBuf::from("/mnt/other")
            ]
        );
    }

    /// A remount without the privilege for it (any process but root) is refused, and reported
    /// as a failure, not taken for done.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unprivileged_remount_is_refused_not_taken_for_done() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let settled = settle(&[dir.path()], |_| true, remount_read_only);
        assert!(matches!(settled[..], [Settled::Failed(_)]), "{settled:?}");
    }

    #[test]
    fn only_event_devices_are_watched() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["event1", "event0", "mice", "js0"] {
            std::fs::write(dir.path().join(name), b"").expect("file");
        }
        assert_eq!(
            devices(dir.path()),
            [dir.path().join("event0"), dir.path().join("event1")]
        );
    }
}
