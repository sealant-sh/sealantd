//! Validated runtime configuration (plan §9).

use std::path::PathBuf;

use sealant_protocol::{
    CapturePolicy, DEFAULT_MAX_FRAME_BYTES, EnvVar, ExecutionId, Limits, NetworkMode, RuntimeId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ConfigError;

/// Default Unix control-socket path inside a workspace.
pub const DEFAULT_SOCKET_PATH: &str = "/run/sealantd.sock";
/// Default workspace (repository/observation) root.
pub const DEFAULT_WORKSPACE_ROOT: &str = "/workspace";

/// A mount whose declared path is bound to a subdirectory of a root mounted elsewhere (ADR-0014).
/// The orchestrator mounts `root_mount_path` at container start; `mount_path` does not exist
/// until a `bindMount` command (or a recorded bind at boot) points it at `<root>/<subpath>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindableMount {
    /// The path the workspace sees, e.g. `/workspace/repo` or `/workspace/repos/api`.
    pub mount_path: PathBuf,
    /// Where the root is mounted inside the container, e.g. `/workspace/.roots/workspace`.
    pub root_mount_path: PathBuf,
    /// The host path backing the root; recorded for provenance only.
    #[serde(default)]
    pub host_root_path: Option<String>,
}

/// One binding: a bindable mount's path pointed at `subpath` under its root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bind {
    /// The bindable mount's declared path.
    pub mount_path: PathBuf,
    /// Relative path under the root; empty means unbound.
    pub subpath: String,
}

/// The primary group of Mend's people (`mend`) where no owner map names one: the gid a user named
/// to run as must have as its primary group under [`People::Reserved`].
pub const PERSON_GID: u32 = 40_000;
/// The lowest uid of Mend's reserved range for its people (Mend's ADR 0016).
pub const PERSON_UID_MIN: u32 = 40_001;
/// The highest uid of Mend's reserved range for its people.
pub const PERSON_UID_MAX: u32 = 49_999;

/// Which users a process may run as when a request names one (`exec`, `openSession` and
/// `dotfiles.apply` take `user`). The daemon decides from the resolved passwd entry, never from
/// what the caller checked: a person with `sudo` in the executor can edit `/etc/passwd`, so a
/// check made before asking the daemon proves nothing on its own. Root and root's group are
/// refused under either rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum People {
    /// No owner map: a uid in Mend's reserved range ([`PERSON_UID_MIN`] to [`PERSON_UID_MAX`])
    /// whose primary group is [`PERSON_GID`].
    #[default]
    Reserved,
    /// The boot's owner map (`SEALANT_CAPTURE_OWNER_MAP`): one of its people's uids or its
    /// change owner's (`worktree`), whose primary group is the map's `gid`.
    Listed {
        /// The map's shared group.
        gid: u32,
        /// The map's people's uids and its change owner's.
        uids: Vec<u32>,
    },
}

impl People {
    /// Whether a user with `uid` and primary group `gid` may run a process here; `Err` says why
    /// not, in plain words.
    ///
    /// # Errors
    /// The uid or the primary group is not one this rule admits.
    pub fn admit(&self, uid: u32, gid: u32) -> Result<(), String> {
        match self {
            Self::Reserved => {
                if !(PERSON_UID_MIN..=PERSON_UID_MAX).contains(&uid) {
                    return Err(format!(
                        "uid {uid} is outside the range of Mend's people \
                         ({PERSON_UID_MIN}-{PERSON_UID_MAX}; no owner map)"
                    ));
                }
                if gid != PERSON_GID {
                    return Err(format!(
                        "uid {uid} has primary group {gid}, not the group of Mend's people \
                         ({PERSON_GID}; no owner map)"
                    ));
                }
            }
            Self::Listed { gid: group, uids } => {
                if !uids.contains(&uid) {
                    return Err(format!(
                        "uid {uid} is not one of this executor's people (owner map)"
                    ));
                }
                if gid != *group {
                    return Err(format!(
                        "uid {uid} has primary group {gid}, not this executor's people's group \
                         {group} (owner map)"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// All runtime configuration. Values are validated by [`RuntimeConfig::validate`] before the
/// daemon reports healthy. Secrets are never emitted; [`RuntimeConfig::sanitized_summary`] exposes
/// only allowlisted, non-secret fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfig {
    /// Daemon instance identity (one per workspace+run).
    pub runtime_id: RuntimeId,
    /// Bound workspace id, when known.
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// Default execution id (the monorepo run/attempt id), when known.
    #[serde(default)]
    pub default_execution_id: Option<ExecutionId>,
    /// Unix control-socket path.
    pub socket_path: PathBuf,
    /// Workspace/repository root that scopes filesystem observation and default cwd.
    pub workspace_root: PathBuf,
    /// Default shell for interactive sessions.
    pub default_shell: String,
    /// Explicit child base environment (never `std::env::vars()`).
    #[serde(default)]
    pub child_env: Vec<EnvVar>,
    /// Literal values the I/O redactor must mask in addition to the values of secret-looking
    /// `child_env` keys — the launcher-provided secret environment, whose names are arbitrary. Never
    /// serialized: this list must not reach a config dump, fingerprint, or telemetry payload.
    #[serde(default, skip_serializing)]
    pub redact_literals: Vec<String>,
    /// `child_env` names a process run as a person never inherits, beyond the named list
    /// (`sealant_process::identity::WITHHELD`): the harness credentials the injector declared
    /// (`SEALANT_HARNESS_ENV_KEYS`), which are the launcher's logins. The project's secrets are not
    /// here: they reach every person.
    #[serde(default)]
    pub person_withheld: Vec<String>,
    /// The users a request may name to run a process as ([`People`]): the boot's owner map's
    /// people when it has one, else Mend's reserved range.
    #[serde(default)]
    pub people: People,
    /// Set `PR_SET_NO_NEW_PRIVS` on the daemon (plan §18), inherited by every child: no child
    /// gains privileges through a setuid binary or file capabilities. On by default. Off only in
    /// a per-person executor (a boot under an owner map, Mend's ADR 0016): every person there has
    /// passwordless `sudo`, which no-new-privileges would break, so it is root by design, not a
    /// sandbox.
    #[serde(default = "default_true")]
    pub no_new_privileges: bool,
    /// Child user id to drop to, when configured.
    #[serde(default)]
    pub child_uid: Option<u32>,
    /// Child group id to drop to, when configured.
    #[serde(default)]
    pub child_gid: Option<u32>,
    /// Bounded resource limits.
    pub limits: Limits,
    /// Default per-stream capture policy.
    pub capture: CapturePolicy,
    /// Heartbeat interval in milliseconds.
    pub heartbeat_interval_ms: u64,
    /// Shutdown grace period in milliseconds.
    pub shutdown_grace_ms: u64,
    /// How long the final capture flush of a shutdown (`SIGTERM`, `SIGINT`,
    /// `runtime.gracefulShutdown`) may take, from the moment the shutdown began, before the
    /// daemon gives up on it and exits `75` with its staging directory kept. `None`: until it
    /// completes. Set from `SEALANT_SHUTDOWN_FINAL_DEADLINE_MS`: the platform's stop grace less
    /// a margin, so the daemon reports "not saved" itself before it is killed.
    #[serde(default)]
    pub shutdown_final_deadline_ms: Option<u64>,
    /// I/O capture chunk size in bytes.
    pub io_chunk_bytes: usize,
    /// Durable spool directory (telemetry pipeline; populated in a later phase).
    #[serde(default)]
    pub spool_dir: Option<PathBuf>,
    /// Directory for per-session durable PTY output journals. `None` falls back to a
    /// runtime-scoped directory under the system temp dir.
    #[serde(default)]
    pub session_journal_dir: Option<PathBuf>,
    /// Per-segment size cap for session journals (two segments retained per session, so on-disk
    /// scrollback per session is bounded at twice this).
    #[serde(default = "default_session_journal_segment_bytes")]
    pub session_journal_segment_bytes: u64,
    /// Tracing log level filter (e.g. `info`).
    pub log_level: String,
    /// Whether to observe the workspace filesystem (baseline snapshot + live watch + final diff).
    #[serde(default)]
    pub watch_filesystem: bool,
    /// Requested network observation mode (may be degraded by capability detection).
    #[serde(default)]
    pub network_mode: NetworkMode,
    /// Additional uids permitted to connect to the control socket (beyond the daemon's own uid and
    /// root). Empty by default.
    #[serde(default)]
    pub allowed_peer_uids: Vec<u32>,
    /// Mounts whose paths are bound to a root subdirectory on demand (ADR-0014).
    #[serde(default)]
    pub bindable_mounts: Vec<BindableMount>,
}

/// Default per-segment size cap for session output journals (16 MiB; two segments retained).
fn default_session_journal_segment_bytes() -> u64 {
    16 * 1024 * 1024
}

/// Default bounded limits for the smallest workspace.
#[must_use]
pub fn default_limits() -> Limits {
    Limits {
        max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        max_processes: 256,
        max_sessions: 64,
        event_queue_capacity: 4096,
        spool_limit_bytes: 512 * 1024 * 1024,
        max_inline_payload_bytes: 256 * 1024,
        io_chunk_bytes: 64 * 1024,
    }
}

/// [`RuntimeConfig::no_new_privileges`]'s default.
fn default_true() -> bool {
    true
}

impl RuntimeConfig {
    /// Construct a configuration with safe defaults for the given runtime id.
    #[must_use]
    pub fn new(runtime_id: RuntimeId) -> Self {
        Self {
            runtime_id,
            workspace_id: None,
            default_execution_id: None,
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            workspace_root: PathBuf::from(DEFAULT_WORKSPACE_ROOT),
            default_shell: "/bin/bash".to_owned(),
            child_env: Vec::new(),
            redact_literals: Vec::new(),
            person_withheld: Vec::new(),
            people: People::Reserved,
            no_new_privileges: true,
            child_uid: None,
            child_gid: None,
            limits: default_limits(),
            capture: CapturePolicy::default(),
            heartbeat_interval_ms: 15_000,
            shutdown_grace_ms: 10_000,
            shutdown_final_deadline_ms: None,
            io_chunk_bytes: 64 * 1024,
            spool_dir: None,
            session_journal_dir: None,
            session_journal_segment_bytes: default_session_journal_segment_bytes(),
            log_level: "info".to_owned(),
            watch_filesystem: false,
            network_mode: NetworkMode::Off,
            allowed_peer_uids: Vec::new(),
            bindable_mounts: Vec::new(),
        }
    }

    /// Validate the configuration. Must succeed before the runtime reports healthy.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] describing the first invalid field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.default_shell.trim().is_empty() {
            return Err(ConfigError::EmptyShell);
        }
        if self.socket_path.parent().is_none() {
            return Err(ConfigError::InvalidSocketPath(
                self.socket_path.display().to_string(),
            ));
        }
        if self.io_chunk_bytes == 0 {
            return Err(ConfigError::NonPositive {
                field: "ioChunkBytes",
            });
        }
        if self.heartbeat_interval_ms == 0 {
            return Err(ConfigError::NonPositive {
                field: "heartbeatIntervalMs",
            });
        }
        if self.limits.max_processes == 0 {
            return Err(ConfigError::NonPositive {
                field: "limits.maxProcesses",
            });
        }
        if self.limits.event_queue_capacity == 0 {
            return Err(ConfigError::NonPositive {
                field: "limits.eventQueueCapacity",
            });
        }
        if u64::try_from(self.io_chunk_bytes).unwrap_or(u64::MAX)
            > u64::from(self.limits.max_frame_bytes)
        {
            return Err(ConfigError::ChunkLargerThanFrame {
                chunk: self.io_chunk_bytes as u64,
                max_frame: u64::from(self.limits.max_frame_bytes),
            });
        }
        Ok(())
    }

    /// A deterministic SHA-256 hex fingerprint of the configuration's *sanitized* form: env keys
    /// contribute, env values do not. The fingerprint is logged, and a hash over secret-bearing
    /// values would hand a log reader an offline-guessing oracle for low-entropy secrets.
    #[must_use]
    pub fn config_hash(&self) -> String {
        let json = serde_json::to_vec(&self.sanitized_fields()).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json);
        hex::encode(hasher.finalize())
    }

    /// A sanitized, secret-free summary suitable for logs and telemetry: the sanitized fields
    /// plus their fingerprint.
    ///
    /// Environment values are never emitted; only the *keys* are listed.
    #[must_use]
    pub fn sanitized_summary(&self) -> serde_json::Value {
        let mut summary = self.sanitized_fields();
        if let Some(object) = summary.as_object_mut() {
            object.insert(
                "configHash".to_owned(),
                serde_json::Value::String(self.config_hash()),
            );
        }
        summary
    }

    /// The secret-free field set both the summary and the fingerprint are built from.
    fn sanitized_fields(&self) -> serde_json::Value {
        let env_keys: Vec<&str> = self.child_env.iter().map(|e| e.key.as_str()).collect();
        serde_json::json!({
            "runtimeId": self.runtime_id,
            "workspaceId": self.workspace_id,
            "defaultExecutionId": self.default_execution_id,
            "socketPath": self.socket_path,
            "workspaceRoot": self.workspace_root,
            "defaultShell": self.default_shell,
            "childEnvKeys": env_keys,
            "childUid": self.child_uid,
            "childGid": self.child_gid,
            "limits": self.limits,
            "capture": self.capture,
            "heartbeatIntervalMs": self.heartbeat_interval_ms,
            "shutdownGraceMs": self.shutdown_grace_ms,
            "shutdownFinalDeadlineMs": self.shutdown_final_deadline_ms,
            "ioChunkBytes": self.io_chunk_bytes,
            "logLevel": self.log_level,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RuntimeConfig {
        RuntimeConfig::new(RuntimeId::new("rt_test"))
    }

    #[test]
    fn defaults_validate() {
        assert!(cfg().validate().is_ok());
    }

    #[test]
    fn without_an_owner_map_only_mend_s_reserved_range_in_its_group_runs() {
        let people = People::default();
        assert_eq!(people, People::Reserved);
        for uid in [PERSON_UID_MIN, 40_012, PERSON_UID_MAX] {
            assert_eq!(people.admit(uid, PERSON_GID), Ok(()), "{uid}");
        }
        for uid in [0, 1000, PERSON_GID, PERSON_UID_MAX + 1, 65_534] {
            let why = people.admit(uid, PERSON_GID).unwrap_err();
            assert!(why.contains(&format!("uid {uid} is outside")), "{why}");
            assert!(why.contains("no owner map"), "{why}");
        }
        for gid in [0, 1000, 40_970] {
            let why = people.admit(40_012, gid).unwrap_err();
            assert!(why.contains(&format!("primary group {gid}")), "{why}");
        }
    }

    #[test]
    fn with_an_owner_map_only_its_people_in_its_group_run() {
        let people = People::Listed {
            gid: 41_000,
            uids: vec![40_012, 40_031],
        };
        assert_eq!(people.admit(40_012, 41_000), Ok(()));
        assert_eq!(people.admit(40_031, 41_000), Ok(()));
        // In Mend's reserved range and group, but not on the map.
        let why = people.admit(40_013, PERSON_GID).unwrap_err();
        assert_eq!(
            why,
            "uid 40013 is not one of this executor's people (owner map)"
        );
        // On the map, in another group.
        let why = people.admit(40_012, PERSON_GID).unwrap_err();
        assert!(why.contains("primary group 40000"), "{why}");
        assert!(why.contains("owner map"), "{why}");
        assert!(people.admit(0, 41_000).is_err());
        assert!(people.admit(40_012, 0).is_err());
        // A map lists whomever it lists, outside the reserved range too.
        let listed = People::Listed {
            gid: 1000,
            uids: vec![1000],
        };
        assert_eq!(listed.admit(1000, 1000), Ok(()));
    }

    #[test]
    fn a_config_without_people_reads_as_the_reserved_range() {
        let json = serde_json::to_value(cfg()).unwrap();
        assert_eq!(json["people"], serde_json::json!({"kind": "reserved"}));
        let mut object = json.as_object().unwrap().clone();
        object.remove("people");
        let read: RuntimeConfig = serde_json::from_value(object.into()).unwrap();
        assert_eq!(read.people, People::Reserved);
    }

    #[test]
    fn empty_shell_is_rejected() {
        let mut c = cfg();
        c.default_shell = "  ".to_owned();
        assert!(matches!(c.validate(), Err(ConfigError::EmptyShell)));
    }

    #[test]
    fn chunk_larger_than_frame_is_rejected() {
        let mut c = cfg();
        c.io_chunk_bytes = (c.limits.max_frame_bytes as usize) + 1;
        assert!(matches!(
            c.validate(),
            Err(ConfigError::ChunkLargerThanFrame { .. })
        ));
    }

    #[test]
    fn config_hash_is_stable_and_summary_hides_env_values() {
        let mut c = cfg();
        c.child_env = vec![EnvVar {
            key: "SECRET_TOKEN".to_owned(),
            value: "super-secret".to_owned(),
        }];
        let h1 = c.config_hash();
        let h2 = c.config_hash();
        assert_eq!(h1, h2);
        let summary = c.sanitized_summary();
        let text = summary.to_string();
        assert!(text.contains("SECRET_TOKEN"));
        assert!(!text.contains("super-secret"));
    }

    #[test]
    fn config_hash_ignores_env_values_and_redact_literals() {
        let mut a = cfg();
        a.child_env = vec![EnvVar {
            key: "DATABASE_URL".to_owned(),
            value: "postgres://one".to_owned(),
        }];
        a.redact_literals = vec!["postgres://one".to_owned()];
        let mut b = a.clone();
        b.child_env[0].value = "postgres://two".to_owned();
        b.redact_literals = vec!["postgres://two".to_owned()];
        // Same keys, different values: the logged fingerprint must not distinguish them.
        assert_eq!(a.config_hash(), b.config_hash());
        // And a serialized config never carries the redact list at all.
        let json = serde_json::to_string(&a).expect("serializable");
        assert!(!json.contains("redactLiterals"));
        assert!(!json.contains("redact_literals"));
    }
}
