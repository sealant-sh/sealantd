//! The `vsock:1026` boot handoff and exit status (§5.3, §6.1, §6.2), shared with `sealantd --vm`.
//!
//! Newline-delimited JSON, one object per line, each carrying `"version": 1`. The runner accepts
//! exactly one connection on port 1026, the one PID 1 makes at boot, and at once closes and unlinks
//! its listener, so no later guest process can dial 2:1026 to read the secret environment or forge
//! an exit status. On that connection, which stays open for the VM's life:
//!
//! - runner → guest, at once: one [`VmBootConfig`] line;
//! - runner → guest, on SIGTERM/SIGINT: `{"version":1,"type":"shutdown"}`;
//! - guest → runner, after `sync()`: `{"version":1,"type":"exit","exitCode":…,"synced":…,"reason":…}`;
//! - runner → guest, once that status is recorded: `{"version":1,"type":"exitAck","accepted":true}`.
//!
//! The runner assembles the boot config from files Sealant stages before it starts the container:
//! the image's saved OCI config (`<digest>.config.json`), the launch material (`boot-env.json`, or
//! `recovery-env.json` in recovery), and the executor's public CA (`executor-ca.pem`, optional).
//! The guest network config is the runner's own: it set up the link.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::net::{GUEST_IP, HOST_IP, MTU, PREFIX_LEN};

pub const PROTOCOL_VERSION: u32 = 1;

/// How the guest boots (`sealantd.mode=` on the kernel command line, and `mode` in the config).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum BootMode {
    /// Overlay root, guest `dockerd`, session channel, egress through `<name>-proxy`.
    Normal,
    /// Clean read-only base, flush and status only; no session channel and no egress.
    Recover,
}

impl BootMode {
    pub fn as_str(self) -> &'static str {
        match self {
            BootMode::Normal => "normal",
            BootMode::Recover => "recover",
        }
    }
}

/// The fields of the image's OCI config the guest applies (`docker export` strips them, so the
/// worker saves them beside the disk).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageConfig {
    #[serde(rename = "Env", default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(rename = "User", default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(
        rename = "WorkingDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub working_dir: Option<String>,
    #[serde(
        rename = "Entrypoint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd", default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
}

/// Env names and argument counts only: an image can bake a credential into an `Env` value or its
/// command line, and this config is logged at boot.
impl fmt::Debug for ImageConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.env.as_ref().map(|env| {
            env.iter()
                .map(|entry| {
                    entry
                        .split_once('=')
                        .map_or(entry.as_str(), |(name, _)| name)
                })
                .collect::<Vec<_>>()
        });
        f.debug_struct("ImageConfig")
            .field("env", &names)
            .field("user", &self.user)
            .field("working_dir", &self.working_dir)
            .field("entrypoint_args", &self.entrypoint.as_ref().map(Vec::len))
            .field("cmd_args", &self.cmd.as_ref().map(Vec::len))
            .finish()
    }
}

/// How the guest configures `eth0`. Absent in recovery, where the guest gets no route out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestNetworkConfig {
    /// `eth0`.
    pub interface: String,
    /// `10.200.0.2/30`.
    pub address: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub mtu: u32,
    pub mac: String,
}

impl GuestNetworkConfig {
    pub fn for_mac(mac: &str) -> Self {
        Self::for_mac_with_mtu(mac, MTU)
    }

    pub fn for_mac_with_mtu(mac: &str, mtu: u32) -> Self {
        Self {
            interface: "eth0".to_owned(),
            address: format!("{GUEST_IP}/{PREFIX_LEN}"),
            gateway: HOST_IP.to_string(),
            dns: vec![HOST_IP.to_string()],
            mtu,
            mac: mac.to_owned(),
        }
    }
}

/// A caller-provided dotfiles archive directory, carried inline: each file by name.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DotfilesArchive {
    /// File name → base64 contents.
    pub files: BTreeMap<String, String>,
}

/// File names only.
impl fmt::Debug for DotfilesArchive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DotfilesArchive")
            .field("files", &self.files.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Where the guest sends its traces and errors, and the trace its boot belongs to. Sealant
/// stages it in the launch material; the runner fills what is missing from its own environment
/// and makes its launch span the guest boot's parent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Telemetry {
    /// W3C: in the staged file the launcher's span, on the frame the runner's launch span.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracestate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sentry_dsn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
}

impl Telemetry {
    /// What the guest gets: what was staged, the runner's own `SENTRY_*` settings (`env`) where
    /// the staged file names none, and the runner's launch span (`parent`) as the guest boot's
    /// parent, or the launcher's when the launch is not recorded.
    #[must_use]
    pub fn for_guest(
        self,
        parent: Option<(String, String)>,
        env: impl Fn(&str) -> Option<String>,
        build_release: Option<&str>,
    ) -> Self {
        let env = |key: &str| env(key).filter(|value| !value.is_empty());
        let (traceparent, tracestate) = match parent {
            Some((parent, state)) => (Some(parent), Some(state).filter(|s| !s.is_empty())),
            None => (self.traceparent, self.tracestate),
        };
        Self {
            traceparent,
            tracestate,
            sentry_dsn: self.sentry_dsn.or_else(|| env("SENTRY_DSN")),
            environment: self.environment.or_else(|| env("SENTRY_ENVIRONMENT")),
            release: self
                .release
                .or_else(|| env("SENTRY_RELEASE"))
                .or_else(|| build_release.filter(|r| !r.is_empty()).map(str::to_owned)),
        }
    }
}

/// Runner → guest, once, on the boot connection.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VmBootConfig {
    pub version: u32,
    pub mode: BootMode,
    pub config: ImageConfig,
    #[serde(default)]
    pub boot_env: BTreeMap<String, String>,
    #[serde(default)]
    pub secret_env: BTreeMap<String, String>,
    /// Start the guest's own `dockerd`. Always false in recovery.
    #[serde(default)]
    pub dockerd: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dotfiles_archive: Option<DotfilesArchive>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_ca_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_config: Option<GuestNetworkConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<Telemetry>,
}

/// Names only: neither secret values, boot env values nor file contents reach a log line.
impl fmt::Debug for VmBootConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmBootConfig")
            .field("version", &self.version)
            .field("mode", &self.mode)
            .field("config", &self.config)
            .field("boot_env", &self.boot_env.keys().collect::<Vec<_>>())
            .field("secret_env", &self.secret_env.keys().collect::<Vec<_>>())
            .field("dockerd", &self.dockerd)
            .field("dotfiles_archive", &self.dotfiles_archive)
            .field("executor_ca_pem", &self.executor_ca_pem.is_some())
            .field("network_config", &self.network_config)
            .field("telemetry", &self.telemetry)
            .finish()
    }
}

/// What the guest reported on its way out, after `sealantd` has `sync()`ed `/dev/vdb`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestExitStatus {
    pub version: u32,
    pub exit_code: i32,
    pub synced: bool,
    pub reason: Option<String>,
}

/// The exit frame as it travels.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExitFrame {
    version: u32,
    #[serde(rename = "type")]
    kind: String,
    exit_code: i32,
    synced: bool,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("not a JSON frame: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame version {0}, expected {PROTOCOL_VERSION}")]
    Version(u32),
    #[error("frame type {0:?}, expected \"exit\"")]
    Type(String),
}

impl GuestExitStatus {
    /// One line from the guest. A frame of another version or type is refused, not guessed at.
    pub fn parse_frame(line: &str) -> Result<Self, FrameError> {
        let frame: ExitFrame = serde_json::from_str(line.trim())?;
        if frame.version != PROTOCOL_VERSION {
            return Err(FrameError::Version(frame.version));
        }
        if frame.kind != "exit" {
            return Err(FrameError::Type(frame.kind));
        }
        Ok(Self {
            version: frame.version,
            exit_code: frame.exit_code,
            synced: frame.synced,
            reason: frame.reason,
        })
    }
}

/// A runner → guest control line, `version` first.
#[derive(Serialize)]
struct ControlFrame {
    version: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<bool>,
}

fn control_line(kind: &'static str, accepted: Option<bool>) -> String {
    let frame = ControlFrame {
        version: PROTOCOL_VERSION,
        kind,
        accepted,
    };
    // A struct of a number, a static string and a bool always serializes.
    let mut line = serde_json::to_string(&frame).unwrap_or_default();
    line.push('\n');
    line
}

/// `{"version":1,"type":"shutdown"}`: power off in order.
pub fn shutdown_line() -> String {
    control_line("shutdown", None)
}

/// `{"version":1,"type":"exitAck","accepted":true}`: the status is recorded; the guest may power
/// off.
pub fn exit_ack_line() -> String {
    control_line("exitAck", Some(true))
}

impl VmBootConfig {
    /// The config as one newline-terminated frame.
    pub fn to_frame(&self) -> Result<String, serde_json::Error> {
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        Ok(line)
    }
}

/// `boot-env.json` / `recovery-env.json` as Sealant stages them in `/run/sealant`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StagedLaunch {
    #[serde(default)]
    mode: Option<BootMode>,
    #[serde(default)]
    boot_env: BTreeMap<String, String>,
    #[serde(default)]
    secret_env: BTreeMap<String, String>,
    #[serde(default)]
    dockerd: bool,
    #[serde(default)]
    dotfiles_archive: Option<DotfilesArchive>,
    #[serde(default)]
    telemetry: Option<Telemetry>,
}

/// Where the staged files are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedFiles {
    /// The image's saved OCI config: the first of these that exists.
    pub image_config: Vec<PathBuf>,
    /// `boot-env.json` (normal) or `recovery-env.json` (recover).
    pub launch: PathBuf,
    pub executor_ca: PathBuf,
}

impl StagedFiles {
    /// The layout §3.1/§5.2 describe: launch material in `run_dir` (the container's
    /// `mend-control` subpath), and the image config staged there or kept beside the base disk.
    pub fn new(run_dir: &Path, images_dir: &Path, digest: &str, mode: BootMode) -> Self {
        let config_name = format!("{digest}.config.json");
        let launch = match mode {
            BootMode::Normal => "boot-env.json",
            BootMode::Recover => "recovery-env.json",
        };
        Self {
            image_config: vec![run_dir.join(&config_name), images_dir.join(&config_name)],
            launch: run_dir.join(launch),
            executor_ca: run_dir.join("executor-ca.pem"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BootConfigError {
    #[error("no image config at any of {0:?}")]
    NoImageConfig(Vec<PathBuf>),
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not valid JSON for its kind: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("{path} says mode {staged:?}, but the runner was started for {runner:?}")]
    ModeMismatch {
        path: PathBuf,
        staged: BootMode,
        runner: BootMode,
    },
    #[error("{0} holds no PEM certificate")]
    NotPem(PathBuf),
}

/// Reads the staged files into the config the guest gets. `network` is `None` in recovery.
pub fn load_boot_config(
    files: &StagedFiles,
    mode: BootMode,
    network: Option<GuestNetworkConfig>,
) -> Result<VmBootConfig, BootConfigError> {
    let config_path = files
        .image_config
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| BootConfigError::NoImageConfig(files.image_config.clone()))?;
    let config = read_image_config(config_path)?;

    let launch_text = read(&files.launch)?;
    let launch: StagedLaunch =
        serde_json::from_str(&launch_text).map_err(|source| BootConfigError::Parse {
            path: files.launch.clone(),
            source,
        })?;
    if let Some(staged) = launch.mode
        && staged != mode
    {
        return Err(BootConfigError::ModeMismatch {
            path: files.launch.clone(),
            staged,
            runner: mode,
        });
    }

    let executor_ca_pem = match std::fs::read_to_string(&files.executor_ca) {
        Ok(pem) if pem.contains("-----BEGIN CERTIFICATE-----") => Some(pem),
        Ok(_) => return Err(BootConfigError::NotPem(files.executor_ca.clone())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(BootConfigError::Read {
                path: files.executor_ca.clone(),
                source,
            });
        }
    };

    Ok(VmBootConfig {
        version: PROTOCOL_VERSION,
        mode,
        config,
        boot_env: launch.boot_env,
        secret_env: launch.secret_env,
        dockerd: mode == BootMode::Normal && launch.dockerd,
        dotfiles_archive: launch.dotfiles_archive,
        executor_ca_pem,
        network_config: match mode {
            BootMode::Normal => network,
            BootMode::Recover => None,
        },
        telemetry: launch.telemetry,
    })
}

/// Accepts the bare OCI config or a whole `docker inspect` object (fields under `Config`).
fn read_image_config(path: &Path) -> Result<ImageConfig, BootConfigError> {
    let text = read(path)?;
    let parse = |source| BootConfigError::Parse {
        path: path.to_owned(),
        source,
    };
    let mut value: serde_json::Value = serde_json::from_str(&text).map_err(parse)?;
    if let Some(inner) = value.get_mut("Config").filter(|v| v.is_object()) {
        value = inner.take();
    }
    serde_json::from_value(value).map_err(parse)
}

fn read(path: &Path) -> Result<String, BootConfigError> {
    std::fs::read_to_string(path).map_err(|source| BootConfigError::Read {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged(dir: &Path, mode: BootMode) -> StagedFiles {
        StagedFiles::new(dir, &dir.join("images"), "sha256-abc", mode)
    }

    #[test]
    fn the_boot_config_frame_has_the_agreed_field_names() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("sha256-abc.config.json"),
            r#"{"Config":{"Env":["PATH=/usr/bin","IMAGE_TOKEN=baked-in"],"User":"mend","WorkingDir":"/workspace","Entrypoint":null,"Cmd":["bash","--token=on-the-command-line"],"Labels":{"a":"b"}}}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("boot-env.json"),
            r#"{"bootEnv":{"MEND_X":"1"},"secretEnv":{"TOKEN":"s3cret"},"dockerd":true,"dotfilesArchive":{"files":{"manifest.json":"e30=","home.tar":"c2VjcmV0LWZpbGU="}},"telemetry":{"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01","sentryDsn":"https://k@sentry.example.com/10"}}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("executor-ca.pem"),
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let config = load_boot_config(
            &staged(tmp.path(), BootMode::Normal),
            BootMode::Normal,
            Some(GuestNetworkConfig::for_mac("02:00:00:00:00:01")),
        )
        .unwrap();
        let frame = config.to_frame().unwrap();
        assert!(frame.ends_with('\n') && !frame[..frame.len() - 1].contains('\n'));
        let json: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["mode"], "normal");
        assert_eq!(json["config"]["Env"][0], "PATH=/usr/bin");
        assert_eq!(json["config"]["User"], "mend");
        assert_eq!(json["config"]["WorkingDir"], "/workspace");
        assert_eq!(json["config"]["Cmd"][0], "bash");
        assert!(json["config"].get("Entrypoint").is_none());
        assert!(json["config"].get("Labels").is_none());
        assert_eq!(json["bootEnv"]["MEND_X"], "1");
        assert_eq!(json["secretEnv"]["TOKEN"], "s3cret");
        assert_eq!(json["dockerd"], true);
        assert_eq!(json["dotfilesArchive"]["files"]["manifest.json"], "e30=");
        assert_eq!(json["networkConfig"]["interface"], "eth0");
        assert!(
            json["executorCaPem"]
                .as_str()
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        assert_eq!(json["networkConfig"]["address"], "10.200.0.2/30");
        assert_eq!(json["networkConfig"]["gateway"], "10.200.0.1");
        assert_eq!(json["networkConfig"]["dns"][0], "10.200.0.1");
        assert_eq!(json["networkConfig"]["mtu"], 1500);
        assert_eq!(
            json["telemetry"]["traceparent"],
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
        assert_eq!(
            json["telemetry"]["sentryDsn"],
            "https://k@sentry.example.com/10"
        );

        let debug = format!("{config:?}");
        assert!(
            debug.contains("TOKEN") && !debug.contains("s3cret"),
            "{debug}"
        );
        assert!(
            debug.contains("home.tar") && !debug.contains("c2VjcmV0LWZpbGU="),
            "{debug}"
        );
        assert!(
            debug.contains("IMAGE_TOKEN")
                && !debug.contains("baked-in")
                && !debug.contains("on-the-command-line"),
            "{debug}"
        );
    }

    #[test]
    fn the_guest_gets_the_launch_span_and_the_runners_settings_where_none_were_staged() {
        let staged = Telemetry {
            traceparent: Some("00-launcher-span".to_owned()),
            environment: Some("preview".to_owned()),
            ..Telemetry::default()
        };
        let env = |key: &str| match key {
            "SENTRY_DSN" => Some("https://runner@sentry.example.com/10".to_owned()),
            "SENTRY_ENVIRONMENT" => Some("production".to_owned()),
            _ => None,
        };
        let guest = staged.clone().for_guest(
            Some(("00-launch-span".to_owned(), String::new())),
            env,
            Some("sealantd@1.0.0"),
        );
        assert_eq!(guest.traceparent.as_deref(), Some("00-launch-span"));
        assert_eq!(guest.tracestate, None);
        assert_eq!(
            guest.sentry_dsn.as_deref(),
            Some("https://runner@sentry.example.com/10")
        );
        assert_eq!(guest.environment.as_deref(), Some("preview"));
        assert_eq!(guest.release.as_deref(), Some("sealantd@1.0.0"));
        // No launch span recorded: the launcher's span is the guest boot's parent.
        let unrecorded = staged.for_guest(None, |_| None, None);
        assert_eq!(unrecorded.traceparent.as_deref(), Some("00-launcher-span"));
        assert_eq!(unrecorded.sentry_dsn, None);
    }

    #[test]
    fn recovery_reads_recovery_env_and_gives_the_guest_no_network() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("images")).unwrap();
        std::fs::write(
            tmp.path().join("images/sha256-abc.config.json"),
            r#"{"Env":["PATH=/bin"]}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("boot-env.json"),
            r#"{"secretEnv":{"A":"normal"}}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("recovery-env.json"),
            r#"{"mode":"recover","secretEnv":{"A":"capture-only"},"dockerd":true}"#,
        )
        .unwrap();
        let config = load_boot_config(
            &staged(tmp.path(), BootMode::Recover),
            BootMode::Recover,
            Some(GuestNetworkConfig::for_mac("02:00:00:00:00:01")),
        )
        .unwrap();
        assert_eq!(config.mode, BootMode::Recover);
        assert_eq!(config.secret_env["A"], "capture-only");
        assert_eq!(config.network_config, None);
        assert_eq!(config.executor_ca_pem, None);
        assert!(!config.dockerd, "recovery never starts the guest's dockerd");
    }

    #[test]
    fn a_launch_file_staged_for_the_other_mode_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("sha256-abc.config.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("boot-env.json"), r#"{"mode":"recover"}"#).unwrap();
        let err = load_boot_config(
            &staged(tmp.path(), BootMode::Normal),
            BootMode::Normal,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, BootConfigError::ModeMismatch { .. }), "{err}");
    }

    #[test]
    fn a_missing_image_config_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("boot-env.json"), "{}").unwrap();
        let err = load_boot_config(
            &staged(tmp.path(), BootMode::Normal),
            BootMode::Normal,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, BootConfigError::NoImageConfig(_)), "{err}");
    }

    #[test]
    fn guest_exit_frames_must_be_version_1_and_type_exit() {
        let ok = GuestExitStatus::parse_frame(
            r#"{"version":1,"type":"exit","exitCode":76,"synced":true,"reason":"never claimed"}"#,
        )
        .unwrap();
        assert_eq!(
            ok,
            GuestExitStatus {
                version: 1,
                exit_code: 76,
                synced: true,
                reason: Some("never claimed".to_owned())
            }
        );
        assert!(matches!(
            GuestExitStatus::parse_frame(
                r#"{"version":2,"type":"exit","exitCode":76,"synced":true}"#
            ),
            Err(FrameError::Version(2))
        ));
        assert!(matches!(
            GuestExitStatus::parse_frame(
                r#"{"version":1,"type":"shutdown","exitCode":76,"synced":true}"#
            ),
            Err(FrameError::Type(_))
        ));
        // The snake_case untagged shape is not this protocol.
        assert!(
            GuestExitStatus::parse_frame(r#"{"version":1,"exit_code":76,"synced":true}"#).is_err()
        );
        assert!(
            GuestExitStatus::parse_frame(r#"{"version":1,"type":"exit","exitCode":76}"#).is_err()
        );
        assert!(GuestExitStatus::parse_frame("garbage").is_err());
    }

    #[test]
    fn control_lines_put_the_version_first() {
        assert_eq!(shutdown_line(), "{\"version\":1,\"type\":\"shutdown\"}\n");
        assert_eq!(
            exit_ack_line(),
            "{\"version\":1,\"type\":\"exitAck\",\"accepted\":true}\n"
        );
    }
}
