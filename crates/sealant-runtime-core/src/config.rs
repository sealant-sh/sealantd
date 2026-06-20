//! Validated runtime configuration (plan §9).

use std::path::PathBuf;

use sealant_protocol::{
    CapturePolicy, DEFAULT_MAX_FRAME_BYTES, EnvVar, ExecutionId, Limits, RuntimeId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ConfigError;

/// Default Unix control-socket path inside a sandbox.
pub const DEFAULT_SOCKET_PATH: &str = "/run/sealantd.sock";
/// Default workspace root inside a sandbox.
pub const DEFAULT_WORKSPACE_ROOT: &str = "/workspace";

/// All runtime configuration. Values are validated by [`RuntimeConfig::validate`] before the
/// daemon reports healthy. Secrets are never emitted; [`RuntimeConfig::sanitized_summary`] exposes
/// only allowlisted, non-secret fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfig {
    /// Daemon instance identity (one per sandbox+run).
    pub runtime_id: RuntimeId,
    /// Bound sandbox id, when known.
    #[serde(default)]
    pub sandbox_id: Option<String>,
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
    /// Tracing log level filter (e.g. `info`).
    pub log_level: String,
}

/// Default bounded limits for the smallest sandbox.
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
            sandbox_id: None,
            default_execution_id: None,
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            workspace_root: PathBuf::from(DEFAULT_WORKSPACE_ROOT),
            default_shell: "/bin/bash".to_owned(),
            child_env: Vec::new(),
            child_uid: None,
            child_gid: None,
            limits: default_limits(),
            capture: CapturePolicy::default(),
            heartbeat_interval_ms: 15_000,
            shutdown_grace_ms: 10_000,
            io_chunk_bytes: 64 * 1024,
            spool_dir: None,
            log_level: "info".to_owned(),
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

    /// A deterministic SHA-256 hex fingerprint of the full configuration.
    #[must_use]
    pub fn config_hash(&self) -> String {
        let json = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json);
        hex::encode(hasher.finalize())
    }

    /// A sanitized, secret-free summary suitable for logs and telemetry.
    ///
    /// Environment values are never emitted; only the *keys* are listed.
    #[must_use]
    pub fn sanitized_summary(&self) -> serde_json::Value {
        let env_keys: Vec<&str> = self.child_env.iter().map(|e| e.key.as_str()).collect();
        serde_json::json!({
            "runtimeId": self.runtime_id,
            "sandboxId": self.sandbox_id,
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
            "configHash": self.config_hash(),
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
}
