//! The boot and exit protocol on vsock port 1026, shared with `sealant-vm-runner`.
//!
//! Newline-delimited JSON, one object per line, each with `"version": 1`. At boot the guest
//! dials the host (CID 2, port 1026) and reads one [`VmBootConfig`]. On its way out, after the
//! data disk is synced, it dials again, writes one [`GuestExitStatus`] and reads one
//! [`ExitAck`] before it powers off: the runner exits 76 (nothing to save) only on a status that
//! says so, so the status must reach it before the VM is gone.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// The protocol version this daemon speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// The longest line read: a boot configuration carries the dotfiles archives inline.
pub const MAX_LINE_BYTES: usize = 64 * 1024 * 1024;

/// How the guest boots (`sealantd.mode=` on the kernel command line).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum VmMode {
    /// The overlay root over the base disk, every service, full control.
    #[default]
    Normal,
    /// The clean base disk, the workspace and home only, status and final flush only.
    Recover,
}

impl VmMode {
    /// Parse `normal` or `recover`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "normal" => Some(Self::Normal),
            "recover" => Some(Self::Recover),
            _ => None,
        }
    }
}

/// The image's saved OCI config (`docker inspect` before `docker export` stripped it), with the
/// OCI field names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImageConfig {
    /// `KEY=VALUE` entries, `PATH` among them.
    #[serde(rename = "Env", default)]
    pub env: Vec<String>,
    /// The image's user. Informational: the daemon runs as root and runs each process as the
    /// person its request names.
    #[serde(rename = "User", default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The image's working directory: the daemon's own working directory until the workspace
    /// is prepared.
    #[serde(
        rename = "WorkingDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub working_dir: Option<String>,
    /// Informational: the daemon is the image's process; what it runs comes from the boot env.
    #[serde(
        rename = "Entrypoint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub entrypoint: Option<Vec<String>>,
    /// Informational, as `Entrypoint`.
    #[serde(rename = "Cmd", default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
}

impl ImageConfig {
    /// The `Env` entries as pairs; an entry without `=` is a name with an empty value, as
    /// Docker treats it.
    #[must_use]
    pub fn env_pairs(&self) -> Vec<(String, String)> {
        self.env
            .iter()
            .filter(|entry| !entry.is_empty())
            .map(|entry| match entry.split_once('=') {
                Some((key, value)) => (key.to_owned(), value.to_owned()),
                None => (entry.clone(), String::new()),
            })
            .collect()
    }
}

/// The guest's side of its network cable. Defaults are the runner's fixed `/30`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConfig {
    /// The guest interface.
    #[serde(default = "default_interface")]
    pub interface: String,
    /// The guest address with its prefix.
    #[serde(default = "default_address")]
    pub address: String,
    /// The default route's gateway (the runner's `tap0`).
    #[serde(default = "default_gateway")]
    pub gateway: String,
    /// Name servers for `/etc/resolv.conf`.
    #[serde(default = "default_dns")]
    pub dns: Vec<String>,
    /// The interface MTU, when the runner sets one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
}

fn default_interface() -> String {
    "eth0".to_owned()
}
fn default_address() -> String {
    "10.200.0.2/30".to_owned()
}
fn default_gateway() -> String {
    "10.200.0.1".to_owned()
}
fn default_dns() -> Vec<String> {
    vec!["10.200.0.1".to_owned()]
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            interface: default_interface(),
            address: default_address(),
            gateway: default_gateway(),
            dns: default_dns(),
            mtu: None,
        }
    }
}

/// A caller-provided dotfiles archive directory (`SEALANT_DOTFILES_ARCHIVE_DIR` on the `docker`
/// runtime), carried inline: each file of the directory, `manifest.json` among them, by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DotfilesArchive {
    /// File name → base64 contents.
    pub files: BTreeMap<String, String>,
}

/// What the runner sends at boot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VmBootConfig {
    /// [`PROTOCOL_VERSION`].
    pub version: u32,
    /// The mode the runner booted the kernel in; must match `sealantd.mode`.
    pub mode: VmMode,
    /// The image's saved config.
    #[serde(default)]
    pub config: ImageConfig,
    /// The `SEALANT_*` boot environment, as the `docker` runtime passes it to `sealantd boot`.
    #[serde(default)]
    pub boot_env: BTreeMap<String, String>,
    /// The launcher's secret environment (`SEALANT_SECRET_ENV_FILE` on `docker`).
    #[serde(default)]
    pub secret_env: BTreeMap<String, String>,
    /// Caller-provided dotfiles archives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dotfiles_archive: Option<DotfilesArchive>,
    /// The executor's public CA certificate (PEM), trusted beside the system roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_ca_pem: Option<String>,
    /// The guest network; absent, the runner's defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_config: Option<NetworkConfig>,
    /// Start the guest's own `dockerd` (normal mode only).
    #[serde(default)]
    pub dockerd: bool,
}

impl std::fmt::Debug for VmBootConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the secret environment's values, nor the boot env's (it may carry tokens).
        f.debug_struct("VmBootConfig")
            .field("version", &self.version)
            .field("mode", &self.mode)
            .field("boot_env_keys", &self.boot_env.keys().collect::<Vec<_>>())
            .field(
                "secret_env_keys",
                &self.secret_env.keys().collect::<Vec<_>>(),
            )
            .field("dotfiles_archive", &self.dotfiles_archive.is_some())
            .field("executor_ca_pem", &self.executor_ca_pem.is_some())
            .field("network_config", &self.network_config)
            .field("dockerd", &self.dockerd)
            .finish_non_exhaustive()
    }
}

/// What the guest sends on its way out, after `sync()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestExitStatus {
    /// [`PROTOCOL_VERSION`].
    pub version: u32,
    /// The daemon's exit code: 0, 75 (capture incomplete), 76 (nothing to save), …
    pub exit_code: i32,
    /// Whether the data disk was synced before this was sent.
    pub synced: bool,
    /// Why, when the exit is not a clean one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The runner's answer to a [`GuestExitStatus`]: it has the status, and the guest may power off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitAck {
    /// [`PROTOCOL_VERSION`].
    pub version: u32,
}

/// Why a frame could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The connection failed.
    #[error("vsock 1026: {0}")]
    Io(#[from] std::io::Error),
    /// The peer closed before a whole line.
    #[error("vsock 1026: the peer closed before a whole line")]
    Closed,
    /// The line exceeded [`MAX_LINE_BYTES`].
    #[error("vsock 1026: a line exceeded {MAX_LINE_BYTES} bytes")]
    TooLong,
    /// Not the JSON this side expects (never quoting it: it may hold secrets).
    #[error("vsock 1026: malformed frame: {0}")]
    Malformed(String),
    /// A version this daemon does not speak.
    #[error("vsock 1026: protocol version {0} is not supported (expected {PROTOCOL_VERSION})")]
    Version(u32),
}

/// Something with a protocol version.
pub trait Versioned {
    /// The frame's declared version.
    fn version(&self) -> u32;
}

impl Versioned for VmBootConfig {
    fn version(&self) -> u32 {
        self.version
    }
}
impl Versioned for GuestExitStatus {
    fn version(&self) -> u32 {
        self.version
    }
}
impl Versioned for ExitAck {
    fn version(&self) -> u32 {
        self.version
    }
}

/// Write `frame` as one line.
///
/// # Errors
/// [`FrameError::Io`] on a failed write.
pub async fn write_frame<W, T>(writer: &mut W, frame: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut line =
        serde_json::to_vec(frame).map_err(|error| FrameError::Malformed(error.to_string()))?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one line as `T`, refusing a version other than [`PROTOCOL_VERSION`].
///
/// # Errors
/// The matching [`FrameError`].
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: AsyncBufRead + Unpin,
    T: for<'de> Deserialize<'de> + Versioned,
{
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(FrameError::Closed);
        }
        let (taken, done) = match available.iter().position(|&byte| byte == b'\n') {
            Some(end) => (end + 1, true),
            None => (available.len(), false),
        };
        if line.len() + taken > MAX_LINE_BYTES + 1 {
            return Err(FrameError::TooLong);
        }
        line.extend_from_slice(&available[..taken]);
        reader.consume(taken);
        if done {
            break;
        }
    }
    // The version first, so a newer runner's frame says why it is refused rather than which
    // field this daemon does not know.
    let probe: serde_json::Value = serde_json::from_slice(&line)
        .map_err(|error| FrameError::Malformed(error.classify_name()))?;
    let version = probe
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| FrameError::Malformed("no version".to_owned()))?;
    let version = u32::try_from(version).map_err(|_| FrameError::Version(u32::MAX))?;
    if version != PROTOCOL_VERSION {
        return Err(FrameError::Version(version));
    }
    let frame: T =
        serde_json::from_value(probe).map_err(|error| FrameError::Malformed(redact(&error)))?;
    debug_assert_eq!(frame.version(), PROTOCOL_VERSION);
    Ok(frame)
}

/// A serde error's kind without the input it quotes.
trait Classify {
    fn classify_name(&self) -> String;
}

impl Classify for serde_json::Error {
    fn classify_name(&self) -> String {
        format!(
            "{:?} at line {} column {}",
            self.classify(),
            self.line(),
            self.column()
        )
    }
}

/// A serde data error, kept only when it names a missing field (a schema name, never a value).
fn redact(error: &serde_json::Error) -> String {
    let text = error.to_string();
    if text.starts_with("missing field") {
        text
    } else {
        error.classify_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    fn boot_config() -> VmBootConfig {
        VmBootConfig {
            version: PROTOCOL_VERSION,
            mode: VmMode::Normal,
            config: ImageConfig {
                env: vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin".to_owned(),
                    "LANG=C.UTF-8".to_owned(),
                ],
                user: Some("root".to_owned()),
                working_dir: Some("/workspace".to_owned()),
                entrypoint: Some(vec!["/usr/local/bin/sealantd".to_owned()]),
                cmd: Some(vec!["boot".to_owned()]),
            },
            boot_env: BTreeMap::from([(
                "SEALANT_WORKSPACE_SOURCE".to_owned(),
                "capture".to_owned(),
            )]),
            secret_env: BTreeMap::from([(
                "SEALANT_CAPTURE_TOKEN".to_owned(),
                "secret-value".to_owned(),
            )]),
            dotfiles_archive: None,
            executor_ca_pem: Some("-----BEGIN CERTIFICATE-----\n".to_owned()),
            network_config: Some(NetworkConfig::default()),
            dockerd: true,
        }
    }

    #[tokio::test]
    async fn a_boot_config_and_an_exit_status_round_trip_as_lines() {
        let (mut runner, guest) = tokio::io::duplex(1024 * 1024);
        let mut guest = BufReader::new(guest);
        let sent = boot_config();
        write_frame(&mut runner, &sent).await.expect("write");
        let status = GuestExitStatus {
            version: PROTOCOL_VERSION,
            exit_code: 76,
            synced: true,
            reason: Some("nothing to save".to_owned()),
        };
        write_frame(&mut runner, &status).await.expect("write");

        let got: VmBootConfig = read_frame(&mut guest).await.expect("boot config");
        assert_eq!(got, sent);
        let got: GuestExitStatus = read_frame(&mut guest).await.expect("status");
        assert_eq!(got, status);
    }

    #[test]
    fn the_wire_names_are_the_runners() {
        let value = serde_json::to_value(boot_config()).expect("json");
        for key in [
            "version",
            "mode",
            "config",
            "bootEnv",
            "secretEnv",
            "executorCaPem",
            "networkConfig",
            "dockerd",
        ] {
            assert!(value.get(key).is_some(), "{key} in {value}");
        }
        for key in ["Env", "User", "WorkingDir", "Entrypoint", "Cmd"] {
            assert!(value["config"].get(key).is_some(), "config.{key}");
        }
        assert_eq!(value["mode"], "normal");

        let status = serde_json::to_value(GuestExitStatus {
            version: 1,
            exit_code: 75,
            synced: true,
            reason: None,
        })
        .expect("json");
        assert_eq!(
            status,
            serde_json::json!({ "version": 1, "exit_code": 75, "synced": true })
        );
    }

    #[test]
    fn a_minimal_boot_config_takes_the_defaults() {
        let parsed: VmBootConfig =
            serde_json::from_str(r#"{"version":1,"mode":"recover"}"#).expect("parse");
        assert_eq!(parsed.mode, VmMode::Recover);
        assert!(parsed.boot_env.is_empty() && parsed.secret_env.is_empty());
        assert!(!parsed.dockerd);
        assert_eq!(NetworkConfig::default().address, "10.200.0.2/30");
    }

    #[tokio::test]
    async fn another_version_is_refused_by_name() {
        let mut reader = BufReader::new(
            &br#"{"version":2,"mode":"normal","future":true}
"#[..],
        );
        match read_frame::<_, VmBootConfig>(&mut reader).await {
            Err(FrameError::Version(2)) => {}
            other => panic!("expected a version refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_truncated_or_malformed_frame_is_refused_without_quoting_it() {
        let mut reader = BufReader::new(&br#"{"version":1,"mode":"normal""#[..]);
        assert!(matches!(
            read_frame::<_, VmBootConfig>(&mut reader).await,
            Err(FrameError::Closed)
        ));
        let mut reader =
            BufReader::new(&b"{\"version\":1,\"secretEnv\":{\"K\":\"hunter2\"}}\n"[..]);
        match read_frame::<_, VmBootConfig>(&mut reader).await {
            Err(FrameError::Malformed(reason)) => {
                assert!(!reason.contains("hunter2"), "{reason}");
            }
            other => panic!("expected malformed (no mode), got {other:?}"),
        }
    }

    #[test]
    fn the_debug_form_never_shows_a_secret() {
        let text = format!("{:?}", boot_config());
        assert!(!text.contains("secret-value"), "{text}");
        assert!(text.contains("SEALANT_CAPTURE_TOKEN"), "{text}");
    }

    #[test]
    fn image_env_entries_become_pairs() {
        let config = ImageConfig {
            env: vec!["A=1".into(), "B=x=y".into(), "C".into(), String::new()],
            ..ImageConfig::default()
        };
        assert_eq!(
            config.env_pairs(),
            vec![
                ("A".to_owned(), "1".to_owned()),
                ("B".to_owned(), "x=y".to_owned()),
                ("C".to_owned(), String::new()),
            ]
        );
    }
}
