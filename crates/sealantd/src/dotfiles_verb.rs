//! `dotfiles.apply` (Mend's per-person layout, its ADR 0016): a person's dotfiles applied into their
//! home, as their user, at their first process in an executor someone else launched. The answer
//! comes once every file is applied; `./install.sh` (each tree's bootstrap) then runs as a managed
//! process of that user, so the caller can start the person's agent beside it and learn how the
//! script went from the process's own events.

use std::path::{Path, PathBuf};

use sealant_process::ProcessRuntime;
use sealant_process::identity::RunAs;
use sealant_protocol::{
    ControlError, ControlErrorCode, DotfilesApplied, DotfilesApplyArgs, DotfilesRepository,
    ExecArgs, RequestId,
};

use crate::boot::config::{
    DEFAULT_DOTFILES_BOOTSTRAP_COMMAND, DotfilesConfig, DotfilesManager, DotfilesTarget,
};
use crate::boot::dotfiles::{self, BootstrapMode, Home, PendingBootstrap};

/// The HTTP username a clone uses when the request names none.
const DEFAULT_HTTP_USERNAME: &str = "x-access-token";

/// Apply `args`; start the bootstraps as one managed process of the user.
pub(crate) async fn apply(
    processes: &ProcessRuntime,
    args: Box<DotfilesApplyArgs>,
    request_id: RequestId,
) -> Result<DotfilesApplied, ControlError> {
    let args = *args;
    let run_as = RunAs::resolve(&args.user).map_err(ControlError::invalid_argument)?;
    let repository = args
        .repository
        .map(repository_config)
        .transpose()
        .map_err(ControlError::invalid_argument)?;
    let archive_dir = args.archive_dir.map(PathBuf::from);
    if repository.is_none() && archive_dir.is_none() {
        return Err(ControlError::invalid_argument(
            "dotfiles.apply names neither a repository nor an archive directory".to_owned(),
        ));
    }
    let home = Home::of(run_as.clone());
    let home_dir = home.dir().to_path_buf();
    let started = std::time::Instant::now();
    let pending = tokio::task::spawn_blocking(move || {
        let mut pending = Vec::new();
        if let Some(config) = &repository {
            // A person's askpass shim goes in their private TMPDIR; the directory named here
            // is a root home's.
            pending.extend(dotfiles::apply_repository(
                config,
                Path::new("/tmp"),
                &home,
                BootstrapMode::Defer,
            )?);
        }
        if let Some(dir) = &archive_dir {
            pending.extend(dotfiles::apply_archives_into(
                dir,
                &home,
                BootstrapMode::Defer,
            )?);
        }
        Ok::<_, crate::boot::BootError>(pending)
    })
    .await
    .map_err(|e| ControlError::internal(e.to_string()))?
    .map_err(|e| {
        ControlError::new(
            ControlErrorCode::ProcessStartFailed,
            format!("dotfiles.apply as {}: {e}", run_as.name),
        )
    })?;
    tracing::info!(
        user = %run_as.name,
        home = %home_dir.display(),
        bootstraps = pending.len(),
        elapsed_ms = started.elapsed().as_millis(),
        "dotfiles applied as the user"
    );
    let bootstrap = match bootstrap_script(&pending) {
        None => None,
        Some(script) => Some(processes.exec(
            ExecArgs {
                execution_id: args.execution_id,
                session_id: None,
                executable: "/bin/sh".to_owned(),
                args: vec!["-c".to_owned(), script],
                cwd: Some(home_dir.to_string_lossy().into_owned()),
                env: Vec::new(),
                stdin: false,
                attach: false,
                timeout_millis: None,
                background: true,
                capture: None,
                graceful_signal: None,
                user: Some(run_as.name.clone()),
            },
            Some(request_id),
        )?),
    };
    Ok(DotfilesApplied {
        user: run_as.name,
        home: home_dir.to_string_lossy().into_owned(),
        bootstrap,
    })
}

/// One shell script running every bootstrap in order, each in its own tree, stopping at the
/// first that fails (as boot does); `None` when there is none.
fn bootstrap_script(pending: &[PendingBootstrap]) -> Option<String> {
    if pending.is_empty() {
        return None;
    }
    Some(
        pending
            .iter()
            .map(|p| {
                format!(
                    "(cd '{}' && {})",
                    p.dir.to_string_lossy().replace('\'', "'\\''"),
                    p.command
                )
            })
            .collect::<Vec<_>>()
            .join(" && "),
    )
}

/// The boot's dotfiles configuration for a requested repository.
fn repository_config(r: DotfilesRepository) -> Result<DotfilesConfig, String> {
    let parse = |value: Option<&str>, default: &str, what: &str| -> Result<String, String> {
        let value = value.unwrap_or(default).trim().to_ascii_lowercase();
        if value.is_empty() {
            return Err(format!("dotfiles.apply: an empty {what}"));
        }
        Ok(value)
    };
    let manager: DotfilesManager = serde_json::from_value(serde_json::Value::String(parse(
        r.manager.as_deref(),
        "auto",
        "manager",
    )?))
    .map_err(|_| format!("dotfiles.apply: unknown manager {:?}", r.manager))?;
    let target: DotfilesTarget = serde_json::from_value(serde_json::Value::String(parse(
        r.target.as_deref(),
        "home",
        "target",
    )?))
    .map_err(|_| format!("dotfiles.apply: unknown target {:?}", r.target))?;
    if r.url.trim().is_empty() {
        return Err("dotfiles.apply: the repository has no URL".to_owned());
    }
    Ok(DotfilesConfig {
        url: r.url,
        reference: r.reference.filter(|s| !s.trim().is_empty()),
        github_installation_repository_id: None,
        manager,
        target,
        bootstrap: r.bootstrap,
        bootstrap_command: r
            .bootstrap_command
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_DOTFILES_BOOTSTRAP_COMMAND.to_owned()),
        http_username: r
            .http_username
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_HTTP_USERNAME.to_owned()),
        http_token: r.http_token.filter(|s| !s.is_empty()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> DotfilesRepository {
        DotfilesRepository {
            url: "https://github.com/o/dots.git".to_owned(),
            reference: None,
            manager: None,
            target: None,
            bootstrap: true,
            bootstrap_command: None,
            http_username: None,
            http_token: Some("t".to_owned()),
        }
    }

    #[test]
    fn a_requested_repository_takes_the_boot_s_defaults() {
        let config = repository_config(repo()).unwrap();
        assert_eq!(config.manager, DotfilesManager::Auto);
        assert_eq!(config.target, DotfilesTarget::Home);
        assert_eq!(config.bootstrap_command, "./install.sh");
        assert_eq!(config.http_username, "x-access-token");
        let mut stow = repo();
        stow.manager = Some("Stow".to_owned());
        stow.target = Some("config".to_owned());
        let config = repository_config(stow).unwrap();
        assert_eq!(config.manager, DotfilesManager::Stow);
        assert_eq!(config.target, DotfilesTarget::Config);
        let mut bad = repo();
        bad.manager = Some("yadm".to_owned());
        assert!(repository_config(bad).is_err());
        let mut no_url = repo();
        no_url.url = " ".to_owned();
        assert!(repository_config(no_url).is_err());
    }

    #[test]
    fn the_bootstraps_run_in_order_each_in_its_tree() {
        assert_eq!(bootstrap_script(&[]), None);
        let script = bootstrap_script(&[
            PendingBootstrap {
                dir: PathBuf::from("/home/m1/.local/share/chezmoi"),
                command: "./install.sh".to_owned(),
            },
            PendingBootstrap {
                dir: PathBuf::from("/home/m1/it's"),
                command: "./setup".to_owned(),
            },
        ])
        .unwrap();
        assert_eq!(
            script,
            "(cd '/home/m1/.local/share/chezmoi' && ./install.sh) && (cd '/home/m1/it'\\''s' && ./setup)"
        );
    }

    #[test]
    fn a_repository_token_is_never_in_its_debug_form() {
        let shown = format!("{:?}", repo());
        assert!(!shown.contains("\"t\""), "{shown}");
        assert!(shown.contains("<redacted>"));
    }
}
