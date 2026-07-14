//! Git clone-time credential materialization (E4/E5) and the clone itself (E9).
//!
//! Credentials are written under the SSH-runtime directory and applied *only* to the clone
//! `Command`'s environment — never to the process env or the harness passthrough — then wiped
//! (E6/E10). This is the typed port of the bash `cleanup_workspace_clone_auth` discipline.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::boot::config::{BootConfig, CloneAuth};
use crate::boot::error::BootError;

/// Credentials scoped to the clone command: env vars to apply and files to wipe afterwards.
#[derive(Debug, Default)]
pub(crate) struct CloneAuthEnv {
    /// Environment variables to apply to the clone command only.
    pub(crate) vars: Vec<(String, String)>,
    /// Files to remove once the clone completes (or fails).
    pub(crate) files: Vec<PathBuf>,
}

impl CloneAuthEnv {
    /// Apply the credential env vars to a clone command.
    pub(crate) fn apply(&self, command: &mut Command) {
        for (key, value) in &self.vars {
            command.env(key, value);
        }
    }

    /// Remove all materialized credential files (best-effort; idempotent).
    pub(crate) fn wipe(&self) {
        for file in &self.files {
            let _ = std::fs::remove_file(file);
        }
    }
}

/// Materialize clone credentials onto disk and into a scoped env (E4/E5).
///
/// # Errors
/// Returns [`BootError`] if a secret cannot be decoded or written.
pub(crate) fn materialize_clone_auth(
    auth: &CloneAuth,
    runtime_dir: &Path,
) -> Result<CloneAuthEnv, BootError> {
    let mut out = CloneAuthEnv::default();
    match auth {
        CloneAuth::None => {}
        CloneAuth::SshKey { key_b64 } => {
            let key = BASE64
                .decode(key_b64.trim())
                .map_err(|e| BootError::base64("SEALANT_WORKSPACE_AUTH_KEY_BASE64", e))?;
            let key_path = runtime_dir.join("repo_ssh_key");
            write_secret_file(&key_path, &key, 0o600)?;
            out.files.push(key_path.clone());
            let git_ssh = format!(
                "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no",
                key_path.display()
            );
            out.vars.push(("GIT_SSH_COMMAND".to_owned(), git_ssh));
        }
        CloneAuth::HttpToken { username, token } => {
            let askpass_path = runtime_dir.join("git-askpass.sh");
            let script = render_askpass(username, token);
            write_secret_file(&askpass_path, script.as_bytes(), 0o700)?;
            out.files.push(askpass_path.clone());
            out.vars
                .push(("GIT_ASKPASS".to_owned(), askpass_path.display().to_string()));
            out.vars
                .push(("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()));
        }
    }
    Ok(out)
}

/// Render a git askpass shim: git invokes it with the prompt as `$1`; a "Username" prompt prints
/// the username, anything else (the password/token prompt) prints the token.
fn render_askpass(username: &str, token: &str) -> String {
    format!(
        "#!/bin/sh\ncase \"$1\" in\n*[Uu]sername*) printf '%s' {} ;;\n*) printf '%s' {} ;;\nesac\n",
        shell_single_quote(username),
        shell_single_quote(token),
    )
}

/// Single-quote a value for safe embedding in a POSIX shell script.
fn shell_single_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\\''");
    format!("'{escaped}'")
}

fn write_secret_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), BootError> {
    std::fs::write(path, contents).map_err(|e| BootError::io_path("write", path, e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| BootError::io_path("chmod", path, e))?;
    Ok(())
}

/// Clone the workspace repository if it is not already present (E9).
///
/// Returns `Ok(false)` if the working directory already contains a checkout (no-op), `Ok(true)` if
/// a clone was performed.
///
/// # Errors
/// Returns [`BootError::Clone`] on a non-zero `git` exit.
pub(crate) fn clone_repo_if_absent(
    config: &BootConfig,
    auth: &CloneAuthEnv,
) -> Result<bool, BootError> {
    let working_directory = &config.workspace.working_directory;
    if working_directory.join(".git").exists() {
        tracing::info!(
            workdir = %working_directory.display(),
            "working directory already contains a checkout; skipping clone"
        );
        return Ok(false);
    }

    if let Some(parent) = working_directory.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BootError::io_path("mkdir -p", parent, e))?;
    }
    // A partial/dirty directory without .git blocks a fresh clone; remove it (E9 `rm -rf`).
    if working_directory.exists() {
        std::fs::remove_dir_all(working_directory)
            .map_err(|e| BootError::io_path("rm -rf", working_directory, e))?;
    }

    let mut command = Command::new("git");
    command.arg("clone");
    // No reference means the remote's default branch — a plain clone resolves it.
    if let Some(reference) = &config.repo.reference {
        command.arg("--branch").arg(reference);
    }
    command.arg(&config.repo.url).arg(working_directory);
    auth.apply(&mut command);

    tracing::info!(
        url = %config.repo.url,
        reference = config.repo.reference.as_deref().unwrap_or("(remote default)"),
        "cloning workspace repository"
    );
    let status = command
        .status()
        .map_err(|e| BootError::Clone(format!("could not spawn git: {e}")))?;
    if !status.success() {
        return Err(BootError::Clone(format!("git clone exited with {status}")));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn askpass_emits_username_then_token() {
        let script = render_askpass("x-access-token", "ghs_abc");
        assert!(script.contains("'x-access-token'"));
        assert!(script.contains("'ghs_abc'"));
        assert!(script.starts_with("#!/bin/sh"));
    }

    #[test]
    fn shell_single_quote_escapes_quotes() {
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn materialize_none_is_empty() {
        let dir = tempfile::tempdir().expect("tmp");
        let out = materialize_clone_auth(&CloneAuth::None, dir.path()).expect("ok");
        assert!(out.vars.is_empty());
        assert!(out.files.is_empty());
    }

    #[test]
    fn materialize_ssh_key_writes_0600_and_sets_git_ssh_command() {
        let dir = tempfile::tempdir().expect("tmp");
        let key_b64 = BASE64.encode(b"PRIVATE KEY MATERIAL");
        let out = materialize_clone_auth(&CloneAuth::SshKey { key_b64 }, dir.path()).expect("ok");
        assert_eq!(out.files.len(), 1);
        let meta = std::fs::metadata(&out.files[0]).expect("stat");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert!(out.vars.iter().any(|(k, _)| k == "GIT_SSH_COMMAND"));
        out.wipe();
        assert!(!out.files[0].exists());
    }

    #[test]
    fn materialize_http_token_writes_askpass_and_env() {
        let dir = tempfile::tempdir().expect("tmp");
        let out = materialize_clone_auth(
            &CloneAuth::HttpToken {
                username: "x-access-token".to_owned(),
                token: "ghs_xyz".to_owned(),
            },
            dir.path(),
        )
        .expect("ok");
        let meta = std::fs::metadata(&out.files[0]).expect("stat");
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        assert!(out.vars.iter().any(|(k, _)| k == "GIT_ASKPASS"));
        assert!(
            out.vars
                .iter()
                .any(|(k, v)| k == "GIT_TERMINAL_PROMPT" && v == "0")
        );
    }

    #[test]
    fn invalid_base64_key_is_fatal() {
        let dir = tempfile::tempdir().expect("tmp");
        let err = materialize_clone_auth(
            &CloneAuth::SshKey {
                key_b64: "!!! not base64 !!!".to_owned(),
            },
            dir.path(),
        )
        .expect_err("should fail");
        assert!(matches!(err, BootError::Base64 { .. }));
    }
}
