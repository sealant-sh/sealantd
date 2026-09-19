//! Remotes the plan names for the worktree's repository (ADR-0015).
//!
//! The executor builds that repository itself: `git init`, then the head's packs. Remotes are
//! configuration of the control plane's own copy and never travel in a capture, so the
//! repository a harness works in has none, and `git push origin` finds no `origin`. `plan.get`
//! answers `remotes`, and this module sets each one after the head is materialized, at boot and
//! again at a `capture.replan`, where a standby learns which worktree it serves.
//!
//! Only a name and a URL travel. How the remote is authenticated stays the control plane's
//! business: Mend points git's ssh at a transport that signs on its own machine.
//!
//! A remote that cannot be set is not worth a session: the failure is logged and the harness
//! runs without it. A name or URL that could read as an option is a control-plane bug, so it
//! fails the boot rather than reaching git.

use std::path::Path;

use sealant_capture::gitpack::GitRepo;
use sealant_capture::registrar::PlanRemote;

use crate::boot::error::BootError;

/// Set `remotes` on the repository at `working_directory`.
///
/// # Errors
/// Returns [`BootError::Config`] when a remote's name or URL is not one this passes to git.
/// A git failure is logged and skipped, not returned.
pub(crate) fn apply(working_directory: &Path, remotes: &[PlanRemote]) -> Result<(), BootError> {
    if remotes.is_empty() {
        return Ok(());
    }
    for remote in remotes {
        validate(remote)?;
    }
    let repo = match GitRepo::open(working_directory) {
        Ok(repo) => repo,
        Err(error) => {
            tracing::warn!(error = %error, "plan remotes skipped: no repository to set them on");
            return Ok(());
        }
    };
    for remote in remotes {
        // The URL may carry a credential (`https://user:token@…`), so it is never logged.
        match repo.set_remote(&remote.name, &remote.url) {
            Ok(change) => tracing::info!(name = %remote.name, change = ?change, "plan remote set"),
            Err(error) => {
                tracing::warn!(name = %remote.name, error = %error, "plan remote skipped")
            }
        }
    }
    Ok(())
}

fn validate(remote: &PlanRemote) -> Result<(), BootError> {
    let refuse = |reason: &str| {
        BootError::config(format!("capture plan remote {:?}: {reason}", remote.name))
    };
    let name = remote.name.as_str();
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if name.is_empty()
        || !name.chars().all(plain)
        || !name.starts_with(|c: char| c.is_ascii_alphanumeric())
        || name.ends_with('.')
        || name.contains("..")
    {
        return Err(refuse(
            "the name must be letters, digits, '.', '_' or '-', starting with a letter or digit",
        ));
    }
    let url = remote.url.as_str();
    if url.is_empty() || url.starts_with('-') || url.chars().any(char::is_control) {
        return Err(refuse(
            "the URL is empty, reads as an option, or holds a control character",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn remote(name: &str, url: &str) -> PlanRemote {
        PlanRemote {
            name: name.to_owned(),
            url: url.to_owned(),
        }
    }

    fn url_of(root: &Path, name: &str) -> Option<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["remote", "get-url", name])
            .output()
            .expect("git");
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    #[test]
    fn adds_updates_and_leaves_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = GitRepo::init(dir.path()).expect("init");
        let first = "git@example.invalid:acme/api.git";
        let second = "ssh://git@example.invalid:2222/srv/git/api.git";

        apply(dir.path(), &[remote("origin", first)]).expect("add");
        assert_eq!(url_of(dir.path(), "origin").as_deref(), Some(first));

        // A re-materialize names the same remote again: nothing changes, nothing fails.
        assert_eq!(
            repo.set_remote("origin", first).expect("same"),
            sealant_capture::gitpack::RemoteChange::Unchanged
        );

        apply(
            dir.path(),
            &[remote("origin", second), remote("upstream", first)],
        )
        .expect("update");
        assert_eq!(url_of(dir.path(), "origin").as_deref(), Some(second));
        assert_eq!(url_of(dir.path(), "upstream").as_deref(), Some(first));
    }

    #[test]
    fn a_remote_the_session_added_survives() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = GitRepo::init(dir.path()).expect("init");
        repo.run(&["remote", "add", "fork", "https://example.invalid/fork.git"])
            .expect("fork");
        apply(
            dir.path(),
            &[remote("origin", "https://example.invalid/api.git")],
        )
        .expect("apply");
        assert_eq!(
            url_of(dir.path(), "fork").as_deref(),
            Some("https://example.invalid/fork.git")
        );
    }

    #[test]
    fn names_and_urls_that_read_as_options_fail_the_boot() {
        let dir = tempfile::tempdir().expect("tempdir");
        GitRepo::init(dir.path()).expect("init");
        for (name, url) in [
            ("", "https://example.invalid/a.git"),
            ("-origin", "https://example.invalid/a.git"),
            ("ori gin", "https://example.invalid/a.git"),
            ("ori/gin", "https://example.invalid/a.git"),
            ("origin..x", "https://example.invalid/a.git"),
            ("origin", ""),
            ("origin", "--upload-pack=sh"),
            ("origin", "https://example.invalid/a.git\nurl = x"),
        ] {
            assert!(
                apply(dir.path(), &[remote(name, url)]).is_err(),
                "{name:?} {url:?}"
            );
            assert_eq!(url_of(dir.path(), "origin"), None);
        }
    }

    #[test]
    fn no_repository_is_logged_not_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        apply(
            dir.path(),
            &[remote("origin", "https://example.invalid/a.git")],
        )
        .expect("skip");
    }
}
