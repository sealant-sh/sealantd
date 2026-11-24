//! The `vsock:1026` boot handoff and exit status (§5.3, §6.1, §6.2).
//!
//! Newline-delimited JSON, one object per line, each carrying `version: 1`. On every guest
//! connection to port 1026 the runner writes one [`VmBootConfig`] line, then reads lines until the
//! guest closes; each valid [`GuestExitStatus`] line is recorded (the last one wins). The guest may
//! keep one connection for both, or connect again at shutdown to send its exit status.
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

/// How the guest configures `eth0`. Absent in recovery, where the guest gets no route out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestNetworkConfig {
    /// `10.200.0.2/30`.
    pub address: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub mtu: u32,
    pub mac: String,
}

impl GuestNetworkConfig {
    pub fn for_mac(mac: &str) -> Self {
        Self {
            address: format!("{GUEST_IP}/{PREFIX_LEN}"),
            gateway: HOST_IP.to_string(),
            dns: vec![HOST_IP.to_string()],
            mtu: MTU,
            mac: mac.to_owned(),
        }
    }
}

/// Runner → guest, once per connection on `vsock:1026`.
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
    /// The dotfiles archive as Sealant staged it (opaque to the runner).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dotfiles_archive: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_ca_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_config: Option<GuestNetworkConfig>,
}

/// Names only: secret values never reach a log line.
impl fmt::Debug for VmBootConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmBootConfig")
            .field("version", &self.version)
            .field("mode", &self.mode)
            .field("config", &self.config)
            .field("boot_env", &self.boot_env.keys().collect::<Vec<_>>())
            .field("secret_env", &self.secret_env.keys().collect::<Vec<_>>())
            .field(
                "dotfiles_archive",
                &self.dotfiles_archive.as_ref().map(String::len),
            )
            .field("executor_ca_pem", &self.executor_ca_pem.is_some())
            .field("network_config", &self.network_config)
            .finish()
    }
}

/// Guest → runner on `vsock:1026`, after `sealantd` has `sync()`ed `/dev/vdb`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestExitStatus {
    pub version: u32,
    pub exit_code: i32,
    pub synced: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("not a JSON frame: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame version {0}, expected {PROTOCOL_VERSION}")]
    Version(u32),
}

impl GuestExitStatus {
    /// One line from the guest. A frame of another version is refused, not guessed at.
    pub fn parse_frame(line: &str) -> Result<Self, FrameError> {
        let status: Self = serde_json::from_str(line.trim())?;
        if status.version != PROTOCOL_VERSION {
            return Err(FrameError::Version(status.version));
        }
        Ok(status)
    }
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
    dotfiles_archive: Option<String>,
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
        dotfiles_archive: launch.dotfiles_archive,
        executor_ca_pem,
        network_config: match mode {
            BootMode::Normal => network,
            BootMode::Recover => None,
        },
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
            r#"{"Config":{"Env":["PATH=/usr/bin"],"User":"mend","WorkingDir":"/workspace","Entrypoint":null,"Cmd":["bash"],"Labels":{"a":"b"}}}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("boot-env.json"),
            r#"{"bootEnv":{"MEND_X":"1"},"secretEnv":{"TOKEN":"s3cret"},"dotfilesArchive":"dGFy"}"#,
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
        assert_eq!(json["dotfilesArchive"], "dGFy");
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

        let debug = format!("{config:?}");
        assert!(
            debug.contains("TOKEN") && !debug.contains("s3cret"),
            "{debug}"
        );
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
            r#"{"mode":"recover","secretEnv":{"A":"capture-only"}}"#,
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
    fn guest_exit_frames_must_be_version_1() {
        let ok =
            GuestExitStatus::parse_frame(r#"{"version":1,"exit_code":76,"synced":true}"#).unwrap();
        assert_eq!(
            ok,
            GuestExitStatus {
                version: 1,
                exit_code: 76,
                synced: true,
                reason: None
            }
        );
        assert!(matches!(
            GuestExitStatus::parse_frame(r#"{"version":2,"exit_code":76,"synced":true}"#),
            Err(FrameError::Version(2))
        ));
        assert!(GuestExitStatus::parse_frame(r#"{"version":1,"exit_code":76}"#).is_err());
        assert!(GuestExitStatus::parse_frame("garbage").is_err());
    }
}
