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
            child_uid: None,
            child_gid: None,
            limits: default_limits(),
            capture: CapturePolicy::default(),
            heartbeat_interval_ms: 15_000,
            shutdown_grace_ms: 10_000,
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
