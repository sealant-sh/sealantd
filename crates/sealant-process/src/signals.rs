//! Signal mapping and process-group signal delivery.

use nix::errno::Errno;
use nix::sys::signal::Signal as NixSignal;
use nix::unistd::Pid;
use sealant_protocol::Signal;

/// Map a protocol [`Signal`] to the host signal.
#[must_use]
pub fn to_nix(signal: Signal) -> NixSignal {
    match signal {
        Signal::Hup => NixSignal::SIGHUP,
        Signal::Int => NixSignal::SIGINT,
        Signal::Quit => NixSignal::SIGQUIT,
        Signal::Term => NixSignal::SIGTERM,
        Signal::Kill => NixSignal::SIGKILL,
        Signal::Usr1 => NixSignal::SIGUSR1,
        Signal::Usr2 => NixSignal::SIGUSR2,
        Signal::Stop => NixSignal::SIGSTOP,
        Signal::Cont => NixSignal::SIGCONT,
    }
}

/// Deliver a signal to an entire process group.
///
/// A group that has already exited (`ESRCH`) is treated as success: the goal — that the group is
/// gone — is already met.
///
/// # Errors
/// Returns the underlying [`Errno`] for failures other than `ESRCH`.
pub fn signal_group(pgid: i32, signal: NixSignal) -> Result<(), Errno> {
    match nix::sys::signal::killpg(Pid::from_raw(pgid), signal) {
        Ok(()) => Ok(()),
        Err(Errno::ESRCH) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_signals() {
        assert_eq!(to_nix(Signal::Term), NixSignal::SIGTERM);
        assert_eq!(to_nix(Signal::Kill), NixSignal::SIGKILL);
    }

    #[test]
    fn signaling_a_dead_group_is_ok() {
        // Process group 2^30 should not exist; ESRCH is swallowed.
        assert!(signal_group(1 << 30, NixSignal::SIGTERM).is_ok());
    }
}
