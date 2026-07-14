//! Typed configuration for `sealantd boot`, loaded once from the `SEALANT_*` environment contract.
//!
//! Every value the legacy bash entrypoint baked inline (workspace root, working directory, repo
//! url/ref, harness banner, shell paths, lifecycle steps, foreground command) now arrives through
//! environment variables: build-static literals as image `ENV`, run-dynamic/secret values via
//! `docker run -e`. [`BootConfig::from_env`] reads them, parses, and validates *before* any side
//! effect, so a misconfigured container fails fast rather than booting half-broken.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::Deserialize;

use crate::boot::error::BootError;

/// Default workspace root when `SEALANT_WORKSPACE_ROOT` is unset.
const DEFAULT_WORKSPACE_ROOT: &str = "/workspace";
/// Default working directory when `SEALANT_WORKING_DIRECTORY` is unset.
const DEFAULT_WORKING_DIRECTORY: &str = "/workspace/repo";
/// Default control socket path.
const DEFAULT_CONTROL_SOCKET: &str = "/run/sealant/control.sock";
/// Default HTTP git/dotfiles username.
const DEFAULT_HTTP_USERNAME: &str = "x-access-token";
/// Default dotfiles bootstrap command.
const DEFAULT_DOTFILES_BOOTSTRAP_COMMAND: &str = "./install.sh";

/// All `SEALANT_*` keys this loader consumes. Used to compute the harness passthrough environment
/// (every other env var) and to redact secrets from it.
const CONSUMED_KEYS: &[&str] = &[
    "SEALANT_WORKSPACE_ROOT",
    "SEALANT_WORKING_DIRECTORY",
    "SEALANT_WORKSPACE_REPO_URL",
    "SEALANT_WORKSPACE_REPO_REF",
    "SEALANT_WORKSPACE_AUTH_KEY_BASE64",
    "SEALANT_WORKSPACE_HTTP_USERNAME",
    "SEALANT_WORKSPACE_HTTP_TOKEN",
    "SEALANT_DOTFILES_RUNTIME_APPLY",
    "SEALANT_DOTFILES_REPO_URL",
    "SEALANT_DOTFILES_REPO_REF",
    "SEALANT_DOTFILES_GITHUB_INSTALLATION_REPOSITORY_ID",
    "SEALANT_DOTFILES_MANAGER",
    "SEALANT_DOTFILES_TARGET",
    "SEALANT_DOTFILES_BOOTSTRAP",
    "SEALANT_DOTFILES_BOOTSTRAP_COMMAND",
    "SEALANT_DOTFILES_HTTP_USERNAME",
    "SEALANT_DOTFILES_HTTP_TOKEN",
    "SEALANT_LIFECYCLE_SETUP_JSON",
    "SEALANT_LIFECYCLE_STARTUP_JSON",
    "SEALANT_FOREGROUND_COMMAND",
    "SEALANT_FOREGROUND_RUN_JSON",
    "SEALANT_HARNESS_LAUNCH_COMMAND",
    "SEALANT_HARNESS_BANNER",
    "SEALANT_OCI_RUNTIME",
    "SEALANT_OS_FAMILY",
    "SEALANT_LOGIN_SHELL_PATH",
    "SEALANT_BASH_SHELL_PATH",
    "SEALANT_CONTROL_SOCKET",
    "SEALANT_WATCH_FILESYSTEM",
    "SEALANT_NETWORK_PROXY",
    "SEALANT_SPOOL_DIR",
    "SEALANT_EXECUTION_ID",
    "SEALANT_WORKSPACE_ID",
];

/// Substring/suffix markers identifying secret env keys that must never reach the harness env.
const SECRET_MARKERS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "APIKEY",
];

/// Whether an env key looks like a secret and should be excluded from the harness passthrough.
fn is_secret_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    SECRET_MARKERS.iter().any(|m| upper.contains(m)) || upper.ends_with("_KEY") || upper == "KEY"
}

/// An abstract source of environment variables, so the loader is unit-testable without touching the
/// real process environment.
pub trait EnvSource {
    /// Return the value of `key`, if present.
    fn get(&self, key: &str) -> Option<String>;
    /// All `(key, value)` pairs (used to compute the harness passthrough environment).
    fn entries(&self) -> Vec<(String, String)>;
}

/// The real process environment.
#[derive(Debug, Default)]
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
    fn entries(&self) -> Vec<(String, String)> {
        std::env::vars().collect()
    }
}

/// A fixed map source, for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct MapEnv(pub std::collections::HashMap<String, String>);

#[cfg(test)]
impl MapEnv {
    /// Build from `(key, value)` string pairs.
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }
}

#[cfg(test)]
impl EnvSource for MapEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
    fn entries(&self) -> Vec<(String, String)> {
        self.0.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

/// Workspace layout (build-static).
#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    /// Workspace root, e.g. `/workspace`.
    pub workspace_root: PathBuf,
    /// Working directory the repo is cloned into and the harness runs in.
    pub working_directory: PathBuf,
}

/// The workspace repository to clone.
#[derive(Debug, Clone)]
pub struct RepoConfig {
    /// Clone URL.
    pub url: String,
    /// Branch/ref to check out; `None` clones the remote's default branch.
    pub reference: Option<String>,
}

/// Git clone authentication (mutually exclusive).
#[derive(Debug, Clone)]
pub enum CloneAuth {
    /// No clone authentication.
    None,
    /// SSH private key (base64) written to disk; drives `GIT_SSH_COMMAND`.
    SshKey {
        /// The base64-encoded private key.
        key_b64: String,
    },
    /// HTTP token via a git askpass shim.
    HttpToken {
        /// Username (default `x-access-token`).
        username: String,
        /// The token/password.
        token: String,
    },
}

/// Dotfiles manager selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotfilesManager {
    /// Auto-detect (chezmoi / stow / copy).
    Auto,
    /// chezmoi.
    Chezmoi,
    /// GNU stow.
    Stow,
    /// Plain copy.
    Copy,
}

/// Where dotfiles are applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotfilesTarget {
    /// `$HOME`.
    Home,
    /// `$HOME/.config`.
    Config,
}

/// Runtime-applied dotfiles configuration (present only when `SEALANT_DOTFILES_RUNTIME_APPLY=1`).
#[derive(Debug, Clone)]
pub struct DotfilesConfig {
    /// Clone URL.
    pub url: String,
    /// Branch/ref.
    pub reference: String,
    /// GitHub installation repository id, when the dotfiles repo is installation-backed.
    pub github_installation_repository_id: Option<String>,
    /// Manager selection.
    pub manager: DotfilesManager,
    /// Apply target.
    pub target: DotfilesTarget,
    /// Whether to run the bootstrap command.
    pub bootstrap: bool,
    /// Bootstrap command (relative to the dotfiles checkout).
    pub bootstrap_command: String,
    /// HTTP username for the dotfiles askpass shim.
    pub http_username: String,
    /// HTTP token (run-dynamic secret).
    pub http_token: Option<String>,
}

/// The shell a lifecycle/foreground step runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Shell {
    /// POSIX `sh -c`.
    Sh,
    /// Login bash (`bash -lc`).
    #[serde(rename = "loginBash", alias = "bash", alias = "login-bash")]
    LoginBash,
}

/// A single lifecycle step.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleStep {
    /// The command line passed to the shell with `-c`/`-lc`.
    pub run: String,
    /// The shell to run it under.
    #[serde(default = "default_step_shell")]
    pub shell: Shell,
    /// Optional working directory override (defaults to the working directory).
    #[serde(default)]
    pub working_directory: Option<PathBuf>,
}

fn default_step_shell() -> Shell {
    Shell::LoginBash
}

/// Lifecycle steps (setup then startup), in order.
#[derive(Debug, Clone, Default)]
pub struct LifecycleConfig {
    /// Setup steps (run first).
    pub setup: Vec<LifecycleStep>,
    /// Startup steps (run after setup).
    pub startup: Vec<LifecycleStep>,
}

/// How the foreground (harness) process is launched.
#[derive(Debug, Clone)]
pub enum ForegroundConfig {
    /// Explicit override: `bash -lc <command>` (run-dynamic).
    Override {
        /// The command line.
        command: String,
    },
    /// A blueprint `command` foreground.
    Command {
        /// The command line.
        run: String,
        /// The shell.
        shell: Shell,
        /// Optional working directory.
        working_directory: Option<PathBuf>,
    },
    /// The default harness launch command.
    Harness {
        /// The harness launch command line.
        launch_command: String,
    },
}

/// JSON shape of `SEALANT_FOREGROUND_RUN_JSON`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ForegroundRunJson {
    run: String,
    #[serde(default = "default_step_shell")]
    shell: Shell,
    #[serde(default)]
    working_directory: Option<PathBuf>,
}

/// OCI runtime in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciRuntime {
    /// runc (default).
    Runc,
    /// gVisor runsc.
    Runsc,
}

/// Base OS family (drives the glibc loader shim and default tool paths).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    /// Fedora.
    Fedora,
    /// Arch.
    Arch,
    /// Nix.
    Nix,
}

/// Resolved shell/tool paths (build-static).
#[derive(Debug, Clone)]
pub struct ShellPaths {
    /// The interactive login shell (e.g. `/usr/bin/zsh`).
    pub login: PathBuf,
    /// The bash path (e.g. `/bin/bash`).
    pub bash: PathBuf,
}

/// Control-server + telemetry knobs.
#[derive(Debug, Clone)]
pub struct ControlConfig {
    /// Control socket path.
    pub socket: PathBuf,
    /// Whether to observe the workspace filesystem.
    pub watch_filesystem: bool,
    /// Whether to route egress through the proxy.
    pub network_proxy: bool,
    /// Optional durable telemetry spool directory.
    pub spool_dir: Option<PathBuf>,
    /// Default execution id, when supplied.
    pub execution_id: Option<String>,
    /// Bound workspace id, when supplied.
    pub workspace_id: Option<String>,
}

/// The fully-parsed, validated boot configuration.
#[derive(Debug, Clone)]
pub struct BootConfig {
    /// Workspace layout.
    pub workspace: WorkspaceConfig,
    /// Repository to clone.
    pub repo: RepoConfig,
    /// Clone authentication.
    pub clone_auth: CloneAuth,
    /// Runtime-applied dotfiles, when configured.
    pub dotfiles: Option<DotfilesConfig>,
    /// Lifecycle steps.
    pub lifecycle: LifecycleConfig,
    /// Foreground (harness) launch.
    pub foreground: ForegroundConfig,
    /// Harness banner printed at startup.
    pub banner: String,
    /// OCI runtime.
    pub oci_runtime: OciRuntime,
    /// OS family.
    pub os_family: OsFamily,
    /// Shell/tool paths.
    pub shells: ShellPaths,
    /// Control/telemetry config.
    pub control: ControlConfig,
    /// Passthrough environment for the harness child (non-consumed, non-secret).
    pub passthrough_env: Vec<(String, String)>,
}

/// Whether a string is one of the truthy tokens `1` / `true`.
fn is_truthy(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "TRUE" | "True")
}

impl BootConfig {
    /// Load and validate the boot configuration from the real process environment.
    ///
    /// # Errors
    /// Returns [`BootError::Config`] if a required value is missing/invalid.
    pub fn from_env() -> Result<Self, BootError> {
        Self::load(&ProcessEnv)
    }

    /// Load and validate from an arbitrary [`EnvSource`] (the testable core of [`from_env`]).
    ///
    /// # Errors
    /// Returns [`BootError::Config`] if a required value is missing/invalid.
    pub fn load(env: &dyn EnvSource) -> Result<Self, BootError> {
        let workspace = WorkspaceConfig {
            workspace_root: env
                .get("SEALANT_WORKSPACE_ROOT")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_WORKSPACE_ROOT.to_owned())
                .into(),
            working_directory: env
                .get("SEALANT_WORKING_DIRECTORY")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_WORKING_DIRECTORY.to_owned())
                .into(),
        };

        let url = env
            .get("SEALANT_WORKSPACE_REPO_URL")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| BootError::config("SEALANT_WORKSPACE_REPO_URL is required"))?;
        let reference = env
            .get("SEALANT_WORKSPACE_REPO_REF")
            .filter(|s| !s.is_empty());
        let repo = RepoConfig { url, reference };

        let clone_auth = Self::load_clone_auth(env);
        let dotfiles = Self::load_dotfiles(env)?;
        let lifecycle = LifecycleConfig {
            setup: parse_lifecycle(env, "SEALANT_LIFECYCLE_SETUP_JSON")?,
            startup: parse_lifecycle(env, "SEALANT_LIFECYCLE_STARTUP_JSON")?,
        };
        let foreground = Self::load_foreground(env)?;

        let banner = env
            .get("SEALANT_HARNESS_BANNER")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Starting workspace".to_owned());

        let oci_runtime = match env.get("SEALANT_OCI_RUNTIME").as_deref() {
            Some("runsc") => OciRuntime::Runsc,
            _ => OciRuntime::Runc,
        };

        let os_family = match env
            .get("SEALANT_OS_FAMILY")
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("fedora") => OsFamily::Fedora,
            Some("arch") => OsFamily::Arch,
            Some("nix") => OsFamily::Nix,
            Some(other) => {
                return Err(BootError::config(format!(
                    "SEALANT_OS_FAMILY has unknown value {other:?} (expected fedora|arch|nix)"
                )));
            }
            None => return Err(BootError::config("SEALANT_OS_FAMILY is required")),
        };

        let shells = ShellPaths {
            login: env
                .get("SEALANT_LOGIN_SHELL_PATH")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| default_login_shell(os_family).to_owned())
                .into(),
            bash: env
                .get("SEALANT_BASH_SHELL_PATH")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/bin/bash".to_owned())
                .into(),
        };

        let control = ControlConfig {
            socket: env
                .get("SEALANT_CONTROL_SOCKET")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_CONTROL_SOCKET.to_owned())
                .into(),
            watch_filesystem: env
                .get("SEALANT_WATCH_FILESYSTEM")
                .is_some_and(|v| is_truthy(&v)),
            network_proxy: env
                .get("SEALANT_NETWORK_PROXY")
                .is_some_and(|v| is_truthy(&v)),
            spool_dir: env
                .get("SEALANT_SPOOL_DIR")
                .filter(|s| !s.is_empty())
                .map(Into::into),
            execution_id: env.get("SEALANT_EXECUTION_ID").filter(|s| !s.is_empty()),
            workspace_id: env.get("SEALANT_WORKSPACE_ID").filter(|s| !s.is_empty()),
        };

        let passthrough_env = passthrough_env(env);

        Ok(Self {
            workspace,
            repo,
            clone_auth,
            dotfiles,
            lifecycle,
            foreground,
            banner,
            oci_runtime,
            os_family,
            shells,
            control,
            passthrough_env,
        })
    }

    fn load_clone_auth(env: &dyn EnvSource) -> CloneAuth {
        if let Some(key) = env
            .get("SEALANT_WORKSPACE_AUTH_KEY_BASE64")
            .filter(|s| !s.is_empty())
        {
            return CloneAuth::SshKey { key_b64: key };
        }
        if let Some(token) = env
            .get("SEALANT_WORKSPACE_HTTP_TOKEN")
            .filter(|s| !s.is_empty())
        {
            let username = env
                .get("SEALANT_WORKSPACE_HTTP_USERNAME")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_HTTP_USERNAME.to_owned());
            return CloneAuth::HttpToken { username, token };
        }
        CloneAuth::None
    }

    fn load_dotfiles(env: &dyn EnvSource) -> Result<Option<DotfilesConfig>, BootError> {
        if !env
            .get("SEALANT_DOTFILES_RUNTIME_APPLY")
            .is_some_and(|v| is_truthy(&v))
        {
            return Ok(None);
        }
        let url = env
            .get("SEALANT_DOTFILES_REPO_URL")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                BootError::config("SEALANT_DOTFILES_REPO_URL is required for runtime dotfiles")
            })?;
        let reference = env
            .get("SEALANT_DOTFILES_REPO_REF")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                BootError::config("SEALANT_DOTFILES_REPO_REF is required for runtime dotfiles")
            })?;
        let github_installation_repository_id = env
            .get("SEALANT_DOTFILES_GITHUB_INSTALLATION_REPOSITORY_ID")
            .filter(|s| !s.is_empty());
        let manager = match env
            .get("SEALANT_DOTFILES_MANAGER")
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("chezmoi") => DotfilesManager::Chezmoi,
            Some("stow") => DotfilesManager::Stow,
            Some("copy") => DotfilesManager::Copy,
            _ => DotfilesManager::Auto,
        };
        let target = match env
            .get("SEALANT_DOTFILES_TARGET")
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("config") => DotfilesTarget::Config,
            _ => DotfilesTarget::Home,
        };
        let bootstrap = env
            .get("SEALANT_DOTFILES_BOOTSTRAP")
            .is_none_or(|v| is_truthy(&v));
        let bootstrap_command = env
            .get("SEALANT_DOTFILES_BOOTSTRAP_COMMAND")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_DOTFILES_BOOTSTRAP_COMMAND.to_owned());
        let http_username = env
            .get("SEALANT_DOTFILES_HTTP_USERNAME")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_HTTP_USERNAME.to_owned());
        let http_token = env
            .get("SEALANT_DOTFILES_HTTP_TOKEN")
            .filter(|s| !s.is_empty());

        // Mirror E11 line 884: an installation-backed dotfiles repo requires a token to clone.
        if github_installation_repository_id.is_some() && http_token.is_none() {
            return Err(BootError::config(
                "SEALANT_DOTFILES_HTTP_TOKEN is required when a GitHub installation repository id is set",
            ));
        }

        Ok(Some(DotfilesConfig {
            url,
            reference,
            github_installation_repository_id,
            manager,
            target,
            bootstrap,
            bootstrap_command,
            http_username,
            http_token,
        }))
    }

    fn load_foreground(env: &dyn EnvSource) -> Result<ForegroundConfig, BootError> {
        if let Some(command) = env
            .get("SEALANT_FOREGROUND_COMMAND")
            .filter(|s| !s.is_empty())
        {
            return Ok(ForegroundConfig::Override { command });
        }
        if let Some(json) = env
            .get("SEALANT_FOREGROUND_RUN_JSON")
            .filter(|s| !s.is_empty())
        {
            let parsed: ForegroundRunJson = serde_json::from_str(&json).map_err(|e| {
                BootError::config(format!(
                    "SEALANT_FOREGROUND_RUN_JSON is not valid JSON: {e}"
                ))
            })?;
            return Ok(ForegroundConfig::Command {
                run: parsed.run,
                shell: parsed.shell,
                working_directory: parsed.working_directory,
            });
        }
        let launch_command = env
            .get("SEALANT_HARNESS_LAUNCH_COMMAND")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                BootError::config(
                    "no foreground command: set SEALANT_FOREGROUND_COMMAND, \
                     SEALANT_FOREGROUND_RUN_JSON, or SEALANT_HARNESS_LAUNCH_COMMAND",
                )
            })?;
        Ok(ForegroundConfig::Harness { launch_command })
    }
}

fn parse_lifecycle(env: &dyn EnvSource, key: &str) -> Result<Vec<LifecycleStep>, BootError> {
    let Some(json) = env.get(key).filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    serde_json::from_str(&json)
        .map_err(|e| BootError::config(format!("{key} is not a valid lifecycle JSON array: {e}")))
}

/// Compute the harness passthrough environment: every env var that is not a consumed `SEALANT_*`
/// key and does not look like a secret.
fn passthrough_env(env: &dyn EnvSource) -> Vec<(String, String)> {
    let consumed: BTreeSet<&str> = CONSUMED_KEYS.iter().copied().collect();
    let mut out: Vec<(String, String)> = env
        .entries()
        .into_iter()
        .filter(|(k, _)| !consumed.contains(k.as_str()) && !is_secret_key(k))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn default_login_shell(family: OsFamily) -> &'static str {
    match family {
        OsFamily::Fedora | OsFamily::Arch => "/usr/bin/zsh",
        OsFamily::Nix => "/bin/bash",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_pairs() -> Vec<(&'static str, &'static str)> {
        vec![
            ("SEALANT_WORKSPACE_REPO_URL", "git@github.com:o/r.git"),
            ("SEALANT_WORKSPACE_REPO_REF", "main"),
            ("SEALANT_OS_FAMILY", "fedora"),
            ("SEALANT_HARNESS_LAUNCH_COMMAND", "claude --dangerously"),
        ]
    }

    fn load_with(extra: &[(&str, &str)]) -> Result<BootConfig, BootError> {
        let mut pairs = base_pairs();
        pairs.extend_from_slice(extra);
        let env = MapEnv::from_pairs(&pairs);
        BootConfig::load(&env)
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg = load_with(&[]).expect("valid");
        assert_eq!(cfg.workspace.workspace_root, PathBuf::from("/workspace"));
        assert_eq!(
            cfg.workspace.working_directory,
            PathBuf::from("/workspace/repo")
        );
        assert_eq!(cfg.repo.url, "git@github.com:o/r.git");
        assert_eq!(cfg.repo.reference.as_deref(), Some("main"));
        assert!(matches!(cfg.clone_auth, CloneAuth::None));
        assert!(cfg.dotfiles.is_none());
        assert_eq!(cfg.os_family, OsFamily::Fedora);
        assert_eq!(cfg.oci_runtime, OciRuntime::Runc);
        assert_eq!(cfg.shells.login, PathBuf::from("/usr/bin/zsh"));
        assert_eq!(
            cfg.control.socket,
            PathBuf::from("/run/sealant/control.sock")
        );
        assert!(!cfg.control.watch_filesystem);
        match cfg.foreground {
            ForegroundConfig::Harness { launch_command } => {
                assert_eq!(launch_command, "claude --dangerously");
            }
            other => panic!("expected harness foreground, got {other:?}"),
        }
    }

    #[test]
    fn missing_repo_ref_means_remote_default_branch() {
        let env = MapEnv::from_pairs(&[
            ("SEALANT_WORKSPACE_REPO_URL", "git@github.com:o/r.git"),
            ("SEALANT_OS_FAMILY", "fedora"),
            ("SEALANT_HARNESS_LAUNCH_COMMAND", "x"),
        ]);
        let cfg = BootConfig::load(&env).expect("valid");
        assert_eq!(cfg.repo.reference, None);
    }

    #[test]
    fn empty_repo_ref_means_remote_default_branch() {
        let env = MapEnv::from_pairs(&[
            ("SEALANT_WORKSPACE_REPO_URL", "git@github.com:o/r.git"),
            ("SEALANT_WORKSPACE_REPO_REF", ""),
            ("SEALANT_OS_FAMILY", "fedora"),
            ("SEALANT_HARNESS_LAUNCH_COMMAND", "x"),
        ]);
        let cfg = BootConfig::load(&env).expect("valid");
        assert_eq!(cfg.repo.reference, None);
    }

    #[test]
    fn missing_repo_url_is_fatal() {
        let env = MapEnv::from_pairs(&[
            ("SEALANT_WORKSPACE_REPO_REF", "main"),
            ("SEALANT_OS_FAMILY", "fedora"),
            ("SEALANT_HARNESS_LAUNCH_COMMAND", "x"),
        ]);
        assert!(BootConfig::load(&env).is_err());
    }

    #[test]
    fn missing_os_family_is_fatal() {
        let env = MapEnv::from_pairs(&[
            ("SEALANT_WORKSPACE_REPO_URL", "u"),
            ("SEALANT_WORKSPACE_REPO_REF", "main"),
            ("SEALANT_HARNESS_LAUNCH_COMMAND", "x"),
        ]);
        assert!(BootConfig::load(&env).is_err());
    }

    #[test]
    fn ssh_key_auth_wins_over_http_token() {
        let cfg = load_with(&[
            ("SEALANT_WORKSPACE_AUTH_KEY_BASE64", "Zm9v"),
            ("SEALANT_WORKSPACE_HTTP_TOKEN", "ghs_xxx"),
        ])
        .expect("valid");
        assert!(matches!(cfg.clone_auth, CloneAuth::SshKey { .. }));
    }

    #[test]
    fn http_token_auth_defaults_username() {
        let cfg = load_with(&[("SEALANT_WORKSPACE_HTTP_TOKEN", "ghs_xxx")]).expect("valid");
        match cfg.clone_auth {
            CloneAuth::HttpToken { username, token } => {
                assert_eq!(username, "x-access-token");
                assert_eq!(token, "ghs_xxx");
            }
            other => panic!("expected http token, got {other:?}"),
        }
    }

    #[test]
    fn dotfiles_runtime_apply_parses_block() {
        let cfg = load_with(&[
            ("SEALANT_DOTFILES_RUNTIME_APPLY", "1"),
            ("SEALANT_DOTFILES_REPO_URL", "https://github.com/o/dots.git"),
            ("SEALANT_DOTFILES_REPO_REF", "main"),
            ("SEALANT_DOTFILES_MANAGER", "chezmoi"),
            ("SEALANT_DOTFILES_TARGET", "config"),
            ("SEALANT_DOTFILES_BOOTSTRAP", "0"),
        ])
        .expect("valid");
        let d = cfg.dotfiles.expect("dotfiles present");
        assert_eq!(d.manager, DotfilesManager::Chezmoi);
        assert_eq!(d.target, DotfilesTarget::Config);
        assert!(!d.bootstrap);
        assert_eq!(d.http_username, "x-access-token");
    }

    #[test]
    fn dotfiles_installation_without_token_is_fatal() {
        let err = load_with(&[
            ("SEALANT_DOTFILES_RUNTIME_APPLY", "1"),
            ("SEALANT_DOTFILES_REPO_URL", "u"),
            ("SEALANT_DOTFILES_REPO_REF", "main"),
            ("SEALANT_DOTFILES_GITHUB_INSTALLATION_REPOSITORY_ID", "123"),
        ])
        .expect_err("should fail without token");
        assert!(format!("{err}").contains("SEALANT_DOTFILES_HTTP_TOKEN"));
    }

    #[test]
    fn lifecycle_json_is_parsed() {
        let cfg = load_with(&[(
            "SEALANT_LIFECYCLE_SETUP_JSON",
            r#"[{"run":"npm ci","shell":"loginBash"},{"run":"echo hi","shell":"sh","workingDirectory":"/tmp"}]"#,
        )])
        .expect("valid");
        assert_eq!(cfg.lifecycle.setup.len(), 2);
        assert_eq!(cfg.lifecycle.setup[0].run, "npm ci");
        assert_eq!(cfg.lifecycle.setup[0].shell, Shell::LoginBash);
        assert_eq!(cfg.lifecycle.setup[1].shell, Shell::Sh);
        assert_eq!(
            cfg.lifecycle.setup[1].working_directory,
            Some(PathBuf::from("/tmp"))
        );
    }

    #[test]
    fn invalid_lifecycle_json_is_fatal() {
        assert!(load_with(&[("SEALANT_LIFECYCLE_SETUP_JSON", "not json")]).is_err());
    }

    #[test]
    fn foreground_override_takes_precedence() {
        let cfg = load_with(&[
            ("SEALANT_FOREGROUND_COMMAND", "sleep infinity"),
            ("SEALANT_FOREGROUND_RUN_JSON", r#"{"run":"x","shell":"sh"}"#),
        ])
        .expect("valid");
        match cfg.foreground {
            ForegroundConfig::Override { command } => assert_eq!(command, "sleep infinity"),
            other => panic!("expected override, got {other:?}"),
        }
    }

    #[test]
    fn foreground_run_json_is_parsed() {
        let cfg = load_with(&[(
            "SEALANT_FOREGROUND_RUN_JSON",
            r#"{"run":"./serve","shell":"loginBash","workingDirectory":"/srv"}"#,
        )])
        .expect("valid");
        match cfg.foreground {
            ForegroundConfig::Command {
                run,
                shell,
                working_directory,
            } => {
                assert_eq!(run, "./serve");
                assert_eq!(shell, Shell::LoginBash);
                assert_eq!(working_directory, Some(PathBuf::from("/srv")));
            }
            other => panic!("expected command foreground, got {other:?}"),
        }
    }

    #[test]
    fn passthrough_drops_consumed_and_secret_keys() {
        let cfg = load_with(&[
            ("SEALANT_WORKSPACE_HTTP_TOKEN", "ghs_secret"),
            ("MY_TOKEN", "should-drop"),
            ("ANTHROPIC_API_KEY", "should-drop"),
            ("PATH", "/usr/bin"),
            ("MY_PLAIN", "keep"),
        ])
        .expect("valid");
        let keys: Vec<&str> = cfg
            .passthrough_env
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert!(keys.contains(&"PATH"));
        assert!(keys.contains(&"MY_PLAIN"));
        assert!(!keys.contains(&"MY_TOKEN"));
        assert!(!keys.contains(&"ANTHROPIC_API_KEY"));
        assert!(!keys.contains(&"SEALANT_WORKSPACE_HTTP_TOKEN"));
        assert!(!keys.contains(&"SEALANT_WORKSPACE_REPO_URL"));
    }

    #[test]
    fn nix_family_uses_nix_defaults() {
        let cfg = load_with(&[("SEALANT_OS_FAMILY", "nix")]).expect("valid");
        assert_eq!(cfg.os_family, OsFamily::Nix);
        assert_eq!(cfg.shells.login, PathBuf::from("/bin/bash"));
    }

    #[test]
    fn runsc_oci_runtime_is_detected() {
        let cfg = load_with(&[("SEALANT_OCI_RUNTIME", "runsc")]).expect("valid");
        assert_eq!(cfg.oci_runtime, OciRuntime::Runsc);
    }
}
