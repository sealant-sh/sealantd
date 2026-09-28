//! Remotes the plan names for the worktree's repository (ADR-0015).
//!
//! The executor builds that repository itself: `git init`, then the head's packs. Remotes are
//! configuration of the control plane's own copy and never travel in a capture, so the
//! repository a harness works in has none, and `git push origin` finds no `origin`. `plan.get`
//! answers `remotes`, and this module adds each one the repository does not have after the head
//! is materialized, at boot and again at a `capture.replan`, where a standby learns which
//! worktree it serves.
//!
//! The callers apply them to a base only: a repository built from an empty chain, or from a
//! capture that carries no `.git/config` (Mend's capture 0). A capture that carries one holds a
//! session's own configuration, and it is the repository's, a remote the user removed included
//! (review 2026-09-28, fourth pass, #8: a fresh executor added it back).
//!
//! A remote the repository already has is never changed. The repository's `.git/config` is
//! captured with the rest of `.git/` (workspace-class bookkeeping), so a remote there is either
//! one a capture carried — the user's own, whatever URL they gave it — or one this module added;
//! setting it back to the plan's URL overwrote a session's `git remote set-url origin <fork>`
//! before any capture held it, and a later push went to the wrong remote (review 2026-09-28
//! #13). A disk the boot resumes as it is (a restart, a recovery boot) gets nothing at all.
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

/// Add each of `remotes` the repository at `working_directory` does not have; one it has, under
/// any URL, is left as it is.
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
        match add_if_absent(&repo, remote) {
            Ok(true) => tracing::info!(name = %remote.name, "plan remote added"),
            Ok(false) => tracing::info!(
                name = %remote.name,
                "the repository has this remote already; kept as it is"
            ),
            Err(error) => {
                tracing::warn!(name = %remote.name, error = %error, "plan remote skipped")
            }
        }
    }
    Ok(())
}

/// Add `remote` unless the repository has a remote of that name (any URL): `true` when added.
fn add_if_absent(
    repo: &GitRepo,
    remote: &PlanRemote,
) -> Result<bool, sealant_capture::gitpack::GitError> {
    let key = format!("remote.{}.url", remote.name);
    if repo.run(&["config", "--local", "--get", &key]).is_ok() {
        return Ok(false);
    }
    repo.run(&["remote", "add", &remote.name, &remote.url])?;
    Ok(true)
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

    /// A remote the repository lacks is added; one it has keeps its URL, whatever the plan says
    /// (review 2026-09-28 #13: `set-url` overwrote the user's `origin`).
    #[test]
    fn adds_what_is_absent_and_never_changes_what_is_there() {
        let dir = tempfile::tempdir().expect("tempdir");
        GitRepo::init(dir.path()).expect("init");
        let first = "git@example.invalid:acme/api.git";
        let second = "ssh://git@example.invalid:2222/srv/git/api.git";

        apply(dir.path(), &[remote("origin", first)]).expect("add");
        assert_eq!(url_of(dir.path(), "origin").as_deref(), Some(first));

        apply(
            dir.path(),
            &[remote("origin", second), remote("upstream", first)],
        )
        .expect("apply again");
        assert_eq!(url_of(dir.path(), "origin").as_deref(), Some(first));
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
