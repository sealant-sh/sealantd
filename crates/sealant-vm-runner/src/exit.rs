//! The runner's exit code (§6.2). Sealant reads exit `76` (`EXIT_NOTHING_TO_SAVE`, the same code
//! `sealantd` uses) as leave to delete the executor's data disk, so the runner may say it only on
//! evidence: a valid `GuestExitStatus { version: 1, exit_code: 76, synced: true }` from the guest
//! and a clean exit of Cloud Hypervisor. A crash, an OOM kill (`137`), a missing or unsynced frame
//! is never `76`.

use std::sync::{Arc, Mutex};

use crate::protocol::{GuestExitStatus, PROTOCOL_VERSION};

/// The guest found nothing to save and its disk is synced: the data disk may be deleted.
pub const EXIT_NOTHING_TO_SAVE: u8 = 76;
/// The runner could not set up or verify the jail, the network or the VM.
pub const EXIT_SETUP_FAILED: u8 = 1;
/// Cloud Hypervisor exited cleanly but the guest sent no valid exit status.
pub const EXIT_NO_GUEST_STATUS: u8 = 3;
/// The guest said exit 76 without having synced its disk.
pub const EXIT_GUEST_UNSYNCED: u8 = 4;

/// How Cloud Hypervisor ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmmExit {
    Code(i32),
    Signal(i32),
}

impl From<std::process::ExitStatus> for VmmExit {
    fn from(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt;
        match (status.code(), status.signal()) {
            (Some(code), _) => VmmExit::Code(code),
            (None, Some(sig)) => VmmExit::Signal(sig),
            (None, None) => VmmExit::Code(i32::from(EXIT_SETUP_FAILED)),
        }
    }
}

/// The latest exit status the guest sent on `vsock:1026`, shared with the boot channel.
#[derive(Debug, Clone, Default)]
pub struct ExitRecorder(Arc<Mutex<Option<GuestExitStatus>>>);

impl ExitRecorder {
    pub fn record(&self, status: GuestExitStatus) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = Some(status);
    }

    pub fn latest(&self) -> Option<GuestExitStatus> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// The runner's exit code from how the VMM ended and what the guest last said.
pub fn runner_exit_code(vmm: VmmExit, guest: Option<&GuestExitStatus>) -> u8 {
    match vmm {
        // 128 + signal, as a shell reports it: SIGKILL (an OOM kill) is 137.
        VmmExit::Signal(sig) => not_76(128 + sig),
        VmmExit::Code(code) if code != 0 => not_76(code),
        VmmExit::Code(_) => match guest {
            Some(status) if status.version == PROTOCOL_VERSION => {
                if status.exit_code == i32::from(EXIT_NOTHING_TO_SAVE) {
                    if status.synced {
                        EXIT_NOTHING_TO_SAVE
                    } else {
                        EXIT_GUEST_UNSYNCED
                    }
                } else {
                    not_76(status.exit_code)
                }
            }
            _ => EXIT_NO_GUEST_STATUS,
        },
    }
}

/// An exit code in `0..=255` that is never 76: anything else that would read as 76 (76 itself, or
/// a value outside the byte range) becomes a plain failure.
fn not_76(code: i32) -> u8 {
    match u8::try_from(code) {
        Ok(EXIT_NOTHING_TO_SAVE) | Err(_) => EXIT_SETUP_FAILED,
        Ok(byte) => byte,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(exit_code: i32, synced: bool) -> GuestExitStatus {
        GuestExitStatus {
            version: 1,
            exit_code,
            synced,
            reason: None,
        }
    }

    #[test]
    fn a_synced_76_and_a_clean_vmm_exit_76() {
        assert_eq!(
            runner_exit_code(VmmExit::Code(0), Some(&status(76, true))),
            76
        );
    }

    #[test]
    fn an_unsynced_76_is_not_76() {
        assert_eq!(
            runner_exit_code(VmmExit::Code(0), Some(&status(76, false))),
            EXIT_GUEST_UNSYNCED
        );
    }

    #[test]
    fn a_vmm_crash_or_oom_kill_is_never_76_whatever_the_guest_said() {
        let synced = status(76, true);
        assert_eq!(runner_exit_code(VmmExit::Signal(9), Some(&synced)), 137);
        assert_eq!(runner_exit_code(VmmExit::Signal(11), Some(&synced)), 139);
        assert_eq!(runner_exit_code(VmmExit::Code(137), Some(&synced)), 137);
        assert_eq!(runner_exit_code(VmmExit::Code(1), Some(&synced)), 1);
        // The VMM itself exiting 76 is not the guest's say-so.
        assert_eq!(runner_exit_code(VmmExit::Code(76), None), EXIT_SETUP_FAILED);
    }

    #[test]
    fn no_frame_or_a_frame_of_another_version_is_not_76() {
        assert_eq!(
            runner_exit_code(VmmExit::Code(0), None),
            EXIT_NO_GUEST_STATUS
        );
        let mut future = status(76, true);
        future.version = 2;
        assert_eq!(
            runner_exit_code(VmmExit::Code(0), Some(&future)),
            EXIT_NO_GUEST_STATUS
        );
    }

    #[test]
    fn other_guest_codes_pass_through_but_never_wrap_to_76() {
        assert_eq!(
            runner_exit_code(VmmExit::Code(0), Some(&status(0, true))),
            0
        );
        assert_eq!(
            runner_exit_code(VmmExit::Code(0), Some(&status(2, false))),
            2
        );
        // 76 + 256 would truncate to 76 as a process exit code.
        assert_eq!(
            runner_exit_code(VmmExit::Code(0), Some(&status(332, true))),
            EXIT_SETUP_FAILED
        );
        assert_eq!(
            runner_exit_code(VmmExit::Code(0), Some(&status(-1, true))),
            EXIT_SETUP_FAILED
        );
    }

    #[test]
    fn the_recorder_keeps_the_last_frame() {
        let rec = ExitRecorder::default();
        assert_eq!(rec.latest(), None);
        rec.record(status(0, true));
        rec.record(status(76, true));
        assert_eq!(rec.latest(), Some(status(76, true)));
    }
}
