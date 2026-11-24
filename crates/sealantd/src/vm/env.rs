//! From what the runner sent to the boot configuration `sealantd boot` runs with: the image's
//! environment under the `SEALANT_*` boot environment, the combined CA bundle, the session
//! endpoint, and, for a recovery boot, everything a recovery must not start taken out.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;

use super::protocol::{DotfilesArchive, VmBootConfig, VmMode};
use crate::boot::config::EnvSource;

/// Where the combined CA bundle is written.
pub const CA_BUNDLE_PATH: &str = "/etc/ssl/certs/sealant-ca-bundle.pem";

/// The variables that point TLS clients at the combined bundle.
pub const CA_ENV_KEYS: [&str; 3] = ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"];

/// The system root bundles, in the order distributions put them; the first readable one is used.
pub const SYSTEM_ROOT_BUNDLES: [&str; 5] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
];

/// Where a guest's capture traffic goes: the host's capture relay.
pub const CAPTURE_DIAL: &str = "vsock:2:1025";

/// Where inline dotfiles archives are written for `SEALANT_DOTFILES_ARCHIVE_DIR`.
pub const DOTFILES_ARCHIVE_DIR: &str = "/run/sealant/dotfiles-archives";

/// The guest `dockerd`'s socket, the workspace Docker endpoint in normal mode.
pub const GUEST_DOCKER_HOST: &str = "unix:///var/run/docker.sock";

/// Keys a recovery boot never takes from the runner: the workspace's Docker daemon (none runs,
/// and a final flush would wait on it as an active writer), the session endpoint (no session
/// channel is forwarded) and the inline dotfiles archives (never written on a recovery). The
/// lifecycle, foreground and harness keys stay: the loader validates them as on the first boot,
/// and a recovery boot runs none of them.
const RECOVERY_DROPPED: &[&str] = &[
    crate::docker::WORKSPACE_DOCKER_HOST_ENV,
    "DOCKER_HOST",
    "SEALANT_DOTFILES_ARCHIVE_DIR",
    "MEND_SESSION_ENDPOINT",
];

/// Where a recovery boot keeps session journals: the writable `/run` tmpfs (it opens no
/// session, but the boot prepares the directory).
pub const RECOVERY_JOURNAL_DIR: &str = "/run/sealant/session-journals";

/// Where a recovery boot may create directories: the tmpfs mounts and the data disk's binds.
/// Everything else is the read-only base disk.
pub const RECOVERY_WRITABLE: [&str; 4] = ["/run", "/tmp", "/workspace", "/home"];

/// Keys PID 1 copies from the boot environment into its own process environment — the ones
/// the daemon reads from it rather than from its configuration (`git` and `chezmoi` found on
/// the image's `PATH`, the capture bounds, the SFTP server, the dotfiles caps). Never a secret.
const PROCESS_ENV_KEYS: &[&str] = &[
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TERM",
    "SEALANT_SFTP_SERVER_PATH",
    "SEALANT_DOTFILES_MAX_UNPACKED_BYTES",
    "SEALANT_DOTFILES_MAX_FILE_BYTES",
];

/// The entries of `env` PID 1 sets in its own process environment ([`PROCESS_ENV_KEYS`], and
/// `SEALANT_CAPTURE_*_SECS`).
#[must_use]
pub fn process_env(env: &VmEnv) -> Vec<(String, String)> {
    env.0
        .iter()
        .filter(|(key, _)| {
            PROCESS_ENV_KEYS.contains(&key.as_str())
                || (key.starts_with("SEALANT_CAPTURE_") && key.ends_with("_SECS"))
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// The hosts file a guest needs when `docker export` left none (or an empty one).
pub const DEFAULT_HOSTS: &str = "127.0.0.1 localhost\n::1 localhost\n";

/// The guest's hostname, set by PID 1 at boot. The kernel starts with `(none)`, and `sudo`
/// printed `unable to resolve host (none)` on every command (SLNT-1324). Docker gives a
/// container its id; a microVM has no runtime to do it, and the image's `/etc/hostname` is the
/// empty file `docker export` leaves where Docker mounts its own.
pub const GUEST_HOSTNAME: &str = "workspace";

/// Whether a line of the hosts file `text` maps `hostname` (any address; names are compared
/// as the resolver compares them, without regard to case).
#[must_use]
pub fn hosts_name(text: &str, hostname: &str) -> bool {
    text.lines().any(|line| {
        let line = line.split('#').next().unwrap_or_default();
        line.split_whitespace()
            .skip(1)
            .any(|name| name.eq_ignore_ascii_case(hostname))
    })
}

/// Make `path`, the guest's hosts file, resolve `localhost` and `hostname`: [`DEFAULT_HOSTS`]
/// and `127.0.1.1 <hostname>` when it is missing or empty (`docker export` leaves an empty one),
/// else the user's file with that line added when no line maps `hostname` already. Whether it
/// wrote.
///
/// # Errors
/// The write failed.
pub fn ensure_hosts(path: &Path, hostname: &str) -> std::io::Result<bool> {
    let name_line = format!("127.0.1.1 {hostname}\n");
    match std::fs::read_to_string(path) {
        Ok(text) if !text.trim().is_empty() => {
            if hosts_name(&text, hostname) {
                return Ok(false);
            }
            let mut text = text;
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&name_line);
            std::fs::write(path, text)?;
            Ok(true)
        }
        _ => {
            let _ = std::fs::remove_file(path);
            std::fs::write(path, format!("{DEFAULT_HOSTS}{name_line}"))?;
            Ok(true)
        }
    }
}

/// The boot environment as an [`EnvSource`]: what `sealantd boot` reads from its process
/// environment on the `docker` runtime, assembled in memory (this crate never mutates its own
/// environment).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VmEnv(pub BTreeMap<String, String>);

impl EnvSource for VmEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
    fn entries(&self) -> Vec<(String, String)> {
        self.0.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

/// What [`assemble`] needs besides the runner's frame.
#[derive(Debug, Clone, Default)]
pub struct Extras {
    /// The combined CA bundle, when the runner sent an executor CA and it was written.
    pub ca_bundle: Option<PathBuf>,
    /// The guest loopback session endpoint (normal mode).
    pub session_endpoint: Option<String>,
    /// The inline dotfiles archives, written (normal mode).
    pub dotfiles_dir: Option<PathBuf>,
}

/// The boot environment for `boot`, in precedence order (later wins): the image's `Env`, the
/// runner's boot env, then what the guest itself decides — the CA variables, the session
/// endpoint, the capture relay (unless the runner named another dial), the guest `dockerd`
/// (normal mode, when asked) and the recovery flag. A recovery boot drops [`RECOVERY_DROPPED`].
#[must_use]
pub fn assemble(boot: &VmBootConfig, extras: &Extras) -> VmEnv {
    let mut env: BTreeMap<String, String> = boot.config.env_pairs().into_iter().collect();
    env.extend(boot.boot_env.iter().map(|(k, v)| (k.clone(), v.clone())));
    if let Some(bundle) = &extras.ca_bundle {
        for key in CA_ENV_KEYS {
            env.insert(key.to_owned(), bundle.display().to_string());
        }
    }
    env.entry("SEALANT_CAPTURE_DIAL".to_owned())
        .or_insert_with(|| CAPTURE_DIAL.to_owned());
    // The launcher's secrets arrive in the frame and are handed to boot in memory, never as a
    // file a variable points at.
    env.remove("SEALANT_SECRET_ENV_FILE");
    match boot.mode {
        VmMode::Normal => {
            if let Some(endpoint) = &extras.session_endpoint {
                env.insert("MEND_SESSION_ENDPOINT".to_owned(), endpoint.clone());
            }
            if let Some(dir) = &extras.dotfiles_dir {
                env.insert(
                    "SEALANT_DOTFILES_ARCHIVE_DIR".to_owned(),
                    dir.display().to_string(),
                );
            }
            if boot.dockerd {
                env.insert(
                    crate::docker::WORKSPACE_DOCKER_HOST_ENV.to_owned(),
                    GUEST_DOCKER_HOST.to_owned(),
                );
            }
        }
        VmMode::Recover => {
            for key in RECOVERY_DROPPED {
                env.remove(*key);
            }
            env.insert("SEALANT_RECOVERY".to_owned(), "1".to_owned());
            // The base disk is read-only: the journals' default under /var/lib cannot be made.
            env.entry("SEALANT_SESSION_JOURNAL_DIR".to_owned())
                .or_insert_with(|| RECOVERY_JOURNAL_DIR.to_owned());
        }
    }
    VmEnv(env)
}

/// The secret environment as `boot` takes it.
#[must_use]
pub fn secret_env(boot: &VmBootConfig) -> Vec<(String, String)> {
    boot.secret_env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// A recovery boot's configuration, whatever the environment said: no workspace Docker daemon,
/// so the final flush stops no container and never waits on a `dockerd` that is not running.
#[must_use]
pub fn clear_recovery_docker(
    mut config: crate::boot::BootConfig,
    mode: VmMode,
) -> crate::boot::BootConfig {
    if mode == VmMode::Recover {
        config.workspace_docker = None;
    }
    config
}

/// A microVM boot's privilege posture, whatever the workspace source: a normal boot leaves
/// no-new-privileges off, so `sudo` and other setuid binaries in the guest work (the guest's
/// own kernel is the isolation boundary, not the shared kernel a container's posture guards);
/// a recovery boot keeps it on, owner map or not, since it runs the clean base to save a disk
/// and has no person to run as. A container boot never comes here.
#[must_use]
pub fn vm_privilege_posture(
    mut config: crate::boot::BootConfig,
    mode: VmMode,
) -> crate::boot::BootConfig {
    config.no_new_privileges = mode == VmMode::Recover;
    config
}

/// The combined CA bundle: the first readable system bundle of `system_bundles`, then the
/// executor CA. Each part ends with a newline so the PEM blocks never run together.
///
/// # Errors
/// The executor CA holds no certificate.
pub fn combined_bundle(system_bundles: &[&Path], executor_ca_pem: &str) -> Result<String, String> {
    if !executor_ca_pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err("the executor CA holds no PEM certificate".to_owned());
    }
    let mut bundle = String::new();
    match system_bundles
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
    {
        Some(roots) => {
            bundle.push_str(&roots);
            if !bundle.ends_with('\n') {
                bundle.push('\n');
            }
        }
        None => tracing::warn!(
            "no system root bundle found; the combined bundle holds the executor CA only"
        ),
    }
    bundle.push_str("# Sealant executor CA\n");
    bundle.push_str(executor_ca_pem.trim_end());
    bundle.push('\n');
    Ok(bundle)
}

/// Write the combined bundle to `path` (`0644`, atomically).
///
/// # Errors
/// What made it impossible.
pub fn write_bundle(path: &Path, executor_ca_pem: &str) -> Result<PathBuf, String> {
    let system: Vec<&Path> = SYSTEM_ROOT_BUNDLES.iter().map(Path::new).collect();
    let bundle = combined_bundle(&system, executor_ca_pem)?;
    write_atomic(path, bundle.as_bytes(), 0o644).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path.to_path_buf())
}

/// Write the inline dotfiles archives into `dir` (`0700`), each file by its plain name.
///
/// # Errors
/// A name that is not a plain file name, contents that are not base64, or a failed write.
pub fn write_dotfiles(dir: &Path, archive: &DotfilesArchive) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    for (name, contents) in &archive.files {
        let plain = !name.is_empty()
            && name != "."
            && name != ".."
            && !name.contains('/')
            && !name.contains('\0');
        if !plain {
            return Err(format!(
                "dotfiles archive file name {name:?} is not a plain name"
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(contents)
            .map_err(|e| format!("dotfiles archive file {name}: {e}"))?;
        write_atomic(&dir.join(name), &bytes, 0o600).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(dir.to_path_buf())
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("sealant-tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// The mode the kernel command line names (`sealantd.mode=normal|recover`), if it names one.
#[must_use]
pub fn mode_from_cmdline(cmdline: &str) -> Option<VmMode> {
    cmdline
        .split_ascii_whitespace()
        .filter_map(|word| word.strip_prefix("sealantd.mode="))
        .next_back()
        .and_then(VmMode::parse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::protocol::{ImageConfig, PROTOCOL_VERSION};

    const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBexecutor\n-----END CERTIFICATE-----";

    fn boot(mode: VmMode) -> VmBootConfig {
        VmBootConfig {
            version: PROTOCOL_VERSION,
            mode,
            config: ImageConfig {
                env: vec![
                    "PATH=/opt/image/bin:/usr/bin".to_owned(),
                    "LANG=C.UTF-8".to_owned(),
                    "DOCKER_HOST=tcp://image-default:2375".to_owned(),
                ],
                ..ImageConfig::default()
            },
            boot_env: BTreeMap::from([
                ("SEALANT_WORKSPACE_SOURCE".to_owned(), "capture".to_owned()),
                ("LANG".to_owned(), "en_GB.UTF-8".to_owned()),
                (
                    crate::docker::WORKSPACE_DOCKER_HOST_ENV.to_owned(),
                    "unix:///var/run/docker.sock".to_owned(),
                ),
                ("SEALANT_LIFECYCLE_SETUP_JSON".to_owned(), "[]".to_owned()),
                ("SEALANT_SECRET_ENV_FILE".to_owned(), "/x".to_owned()),
            ]),
            secret_env: BTreeMap::from([("SEALANT_CAPTURE_TOKEN".to_owned(), "t".to_owned())]),
            dotfiles_archive: None,
            executor_ca_pem: Some(CA.to_owned()),
            network_config: None,
            dockerd: true,
        }
    }

    fn extras() -> Extras {
        Extras {
            ca_bundle: Some(PathBuf::from(CA_BUNDLE_PATH)),
            session_endpoint: Some("http://127.0.0.1:41000".to_owned()),
            dotfiles_dir: Some(PathBuf::from(DOTFILES_ARCHIVE_DIR)),
        }
    }

    #[test]
    fn the_image_env_is_the_base_the_boot_env_overrides_and_the_ca_is_exported() {
        let env = assemble(&boot(VmMode::Normal), &extras());
        assert_eq!(env.get("PATH").as_deref(), Some("/opt/image/bin:/usr/bin"));
        assert_eq!(env.get("LANG").as_deref(), Some("en_GB.UTF-8"));
        for key in CA_ENV_KEYS {
            assert_eq!(env.get(key).as_deref(), Some(CA_BUNDLE_PATH), "{key}");
        }
        assert_eq!(
            env.get("MEND_SESSION_ENDPOINT").as_deref(),
            Some("http://127.0.0.1:41000")
        );
        assert_eq!(
            env.get("SEALANT_CAPTURE_DIAL").as_deref(),
            Some(CAPTURE_DIAL)
        );
        assert_eq!(
            env.get(crate::docker::WORKSPACE_DOCKER_HOST_ENV).as_deref(),
            Some(GUEST_DOCKER_HOST)
        );
        assert_eq!(env.get("SEALANT_SECRET_ENV_FILE"), None);
        assert_eq!(env.get("SEALANT_RECOVERY"), None);
    }

    #[test]
    fn a_runner_named_dial_wins_over_the_default_relay() {
        let mut config = boot(VmMode::Normal);
        config
            .boot_env
            .insert("SEALANT_CAPTURE_DIAL".to_owned(), "vsock:2:2025".to_owned());
        let env = assemble(&config, &extras());
        assert_eq!(
            env.get("SEALANT_CAPTURE_DIAL").as_deref(),
            Some("vsock:2:2025")
        );
    }

    #[test]
    fn a_recovery_boot_has_no_docker_endpoint_session_or_dotfiles() {
        let env = assemble(&boot(VmMode::Recover), &extras());
        for key in RECOVERY_DROPPED {
            assert_eq!(env.get(key), None, "{key}");
        }
        assert_eq!(env.get("SEALANT_RECOVERY").as_deref(), Some("1"));
        assert_eq!(
            env.get("SEALANT_CAPTURE_DIAL").as_deref(),
            Some(CAPTURE_DIAL)
        );
        // Still the image's PATH and the CA bundle: the final flush's git and TLS need them.
        assert_eq!(env.get("PATH").as_deref(), Some("/opt/image/bin:/usr/bin"));
        assert_eq!(env.get("SSL_CERT_FILE").as_deref(), Some(CA_BUNDLE_PATH));
        // And the endpoint the boot loader derives from them is none.
        assert_eq!(
            crate::docker::workspace_endpoint(
                env.get(crate::docker::WORKSPACE_DOCKER_HOST_ENV).as_deref(),
                env.get("DOCKER_HOST").as_deref(),
            ),
            None
        );
    }

    /// A recovery boot runs on the read-only base disk: every directory its preparation makes
    /// is on a tmpfs or the data disk, never under `/var`, `/etc`, `/root` or anywhere else of
    /// the base's.
    #[test]
    fn a_recovery_boot_makes_no_directory_on_the_read_only_base() {
        let mut runner = boot(VmMode::Recover);
        runner.boot_env.extend([
            (
                "SEALANT_CAPTURE_ENDPOINT".to_owned(),
                "http://mend:3106/channel".to_owned(),
            ),
            (
                "SEALANT_HARNESS_LAUNCH_COMMAND".to_owned(),
                "claude".to_owned(),
            ),
            ("SEALANT_OS_FAMILY".to_owned(), "ubuntu".to_owned()),
        ]);
        let env = assemble(&runner, &Extras::default());
        assert_eq!(
            env.get("SEALANT_SESSION_JOURNAL_DIR").as_deref(),
            Some(RECOVERY_JOURNAL_DIR)
        );
        let config = crate::boot::BootConfig::load(&env).expect("recovery config");
        assert!(config.recovery);
        let dirs = crate::boot::workspace_dirs(&config);
        assert!(!dirs.is_empty());
        for dir in &dirs {
            assert!(
                RECOVERY_WRITABLE.iter().any(|root| dir.starts_with(root)),
                "{} is on the read-only base",
                dir.display()
            );
        }
        // A journal directory the runner named is kept as named.
        let mut named = runner.clone();
        named.boot_env.insert(
            "SEALANT_SESSION_JOURNAL_DIR".to_owned(),
            "/workspace/.journals".to_owned(),
        );
        assert_eq!(
            assemble(&named, &Extras::default())
                .get("SEALANT_SESSION_JOURNAL_DIR")
                .as_deref(),
            Some("/workspace/.journals")
        );
    }

    /// The boot config as `sealantd --vm` loads it for `mode`: a capture source, or a clone one,
    /// with an owner map when given one.
    fn vm_boot_config(
        mode: VmMode,
        source: &str,
        owner_map: Option<&str>,
    ) -> crate::boot::BootConfig {
        let mut runner = boot(mode);
        let (key, value) = match source {
            "clone" => ("SEALANT_WORKSPACE_REPO_URL", "git@github.com:o/r.git"),
            _ => ("SEALANT_CAPTURE_ENDPOINT", "http://mend:3106/channel"),
        };
        runner.boot_env.extend([
            ("SEALANT_WORKSPACE_SOURCE".to_owned(), source.to_owned()),
            (key.to_owned(), value.to_owned()),
            (
                "SEALANT_HARNESS_LAUNCH_COMMAND".to_owned(),
                "claude".to_owned(),
            ),
            ("SEALANT_OS_FAMILY".to_owned(), "ubuntu".to_owned()),
        ]);
        if let Some(map) = owner_map {
            runner
                .boot_env
                .insert("SEALANT_CAPTURE_OWNER_MAP".to_owned(), map.to_owned());
        }
        let env = assemble(&runner, &Extras::default());
        crate::boot::BootConfig::load(&env).expect("vm boot config")
    }

    const OWNER_MAP: &str = r#"{"gid":40000,"worktree":40012,"people":{"acct_a":40012}}"#;

    /// A normal microVM boot leaves no-new-privileges off whatever its source, so guest `sudo`
    /// works: a standalone clone, a capture with no owner map, a per-person capture.
    #[test]
    fn a_normal_vm_boot_leaves_no_new_privileges_off_for_every_source() {
        for (source, owner_map) in [
            ("clone", None),
            ("capture", None),
            ("capture", Some(OWNER_MAP)),
        ] {
            let loaded = vm_boot_config(VmMode::Normal, source, owner_map);
            let config = vm_privilege_posture(
                clear_recovery_docker(loaded, VmMode::Normal),
                VmMode::Normal,
            );
            assert!(!config.no_new_privileges, "{source} {owner_map:?}");
        }
    }

    /// A recovery boot keeps no-new-privileges on, even under an owner map and even when the
    /// container posture had left it off (a root daemon loading a per-person capture does).
    #[test]
    fn a_recovery_vm_boot_keeps_no_new_privileges_on_even_with_an_owner_map() {
        let mut per_person = vm_boot_config(VmMode::Recover, "capture", Some(OWNER_MAP));
        assert!(per_person.recovery);
        assert!(matches!(
            &per_person.source,
            crate::boot::config::WorkspaceSource::Capture(c) if c.owners.is_some()
        ));
        per_person.no_new_privileges = false;
        let config = vm_privilege_posture(
            clear_recovery_docker(per_person, VmMode::Recover),
            VmMode::Recover,
        );
        assert!(config.no_new_privileges);
        assert_eq!(config.workspace_docker, None);

        let plain = vm_boot_config(VmMode::Recover, "capture", None);
        assert!(vm_privilege_posture(plain, VmMode::Recover).no_new_privileges);
    }

    #[test]
    fn only_settings_the_daemon_reads_reach_its_own_environment() {
        let mut runner = boot(VmMode::Normal);
        runner.boot_env.extend([
            (
                "SEALANT_CAPTURE_GIT_LIMIT_SECS".to_owned(),
                "1200".to_owned(),
            ),
            (
                "SEALANT_SFTP_SERVER_PATH".to_owned(),
                "/usr/lib/sftp".to_owned(),
            ),
            ("SEALANT_CAPTURE_TOKEN".to_owned(), "secret".to_owned()),
            ("GITHUB_TOKEN".to_owned(), "secret".to_owned()),
        ]);
        let set = process_env(&assemble(&runner, &extras()));
        let keys: Vec<&str> = set.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "LANG",
                "PATH",
                "SEALANT_CAPTURE_GIT_LIMIT_SECS",
                "SEALANT_SFTP_SERVER_PATH"
            ]
        );
        assert!(set.contains(&("PATH".to_owned(), "/opt/image/bin:/usr/bin".to_owned())));
        assert!(!set.iter().any(|(_, v)| v == "secret"));
    }

    #[test]
    fn a_missing_or_empty_hosts_file_is_filled_with_localhost_and_the_hostname() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hosts = dir.path().join("hosts");
        let filled = format!("{DEFAULT_HOSTS}127.0.1.1 {GUEST_HOSTNAME}\n");
        assert!(ensure_hosts(&hosts, GUEST_HOSTNAME).expect("missing"));
        assert_eq!(std::fs::read_to_string(&hosts).expect("hosts"), filled);
        std::fs::write(&hosts, "  \n").expect("empty");
        assert!(ensure_hosts(&hosts, GUEST_HOSTNAME).expect("empty"));
        assert_eq!(std::fs::read_to_string(&hosts).expect("hosts"), filled);
        // Once it resolves, the file is left alone.
        assert!(!ensure_hosts(&hosts, GUEST_HOSTNAME).expect("again"));
        assert_eq!(std::fs::read_to_string(&hosts).expect("hosts"), filled);
    }

    /// The user's own hosts file keeps every line, and gains the hostname only when no line
    /// maps it already.
    #[test]
    fn a_real_hosts_file_is_kept_and_gains_the_hostname_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "10.0.0.1 db").expect("real");
        assert!(ensure_hosts(&hosts, GUEST_HOSTNAME).expect("added"));
        assert_eq!(
            std::fs::read_to_string(&hosts).expect("hosts"),
            format!("10.0.0.1 db\n127.0.1.1 {GUEST_HOSTNAME}\n")
        );
        assert!(!ensure_hosts(&hosts, GUEST_HOSTNAME).expect("kept"));
        let own = "127.0.0.1 localhost Workspace\n";
        std::fs::write(&hosts, own).expect("own");
        assert!(!ensure_hosts(&hosts, GUEST_HOSTNAME).expect("own kept"));
        assert_eq!(std::fs::read_to_string(&hosts).expect("hosts"), own);
    }

    #[test]
    fn a_hostname_is_mapped_by_a_name_column_only_and_not_in_a_comment() {
        assert!(hosts_name("127.0.1.1\tworkspace\n", "workspace"));
        assert!(hosts_name(
            "::1 localhost ip6-localhost workspace",
            "workspace"
        ));
        assert!(!hosts_name("# 127.0.1.1 workspace\n", "workspace"));
        assert!(!hosts_name(
            "127.0.0.1 localhost # workspace\n",
            "workspace"
        ));
        assert!(
            !hosts_name("workspace 10.0.0.1\n", "workspace"),
            "an address column"
        );
        assert!(!hosts_name("127.0.0.1 workspaces\n", "workspace"));
        assert!(!GUEST_HOSTNAME.is_empty());
    }

    #[test]
    fn the_combined_bundle_is_the_system_roots_then_the_executor_ca() {
        let dir = tempfile::tempdir().expect("tempdir");
        let roots = dir.path().join("roots.pem");
        std::fs::write(
            &roots,
            "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----",
        )
        .expect("roots");
        let missing = dir.path().join("absent.pem");
        let bundle = combined_bundle(&[missing.as_path(), roots.as_path()], CA).expect("bundle");
        let root_at = bundle.find("ROOT").expect("roots in the bundle");
        let ca_at = bundle
            .find("MIIBexecutor")
            .expect("executor CA in the bundle");
        assert!(root_at < ca_at);
        assert_eq!(bundle.matches("-----BEGIN CERTIFICATE-----").count(), 2);
        assert!(!bundle.contains("-----END CERTIFICATE----------BEGIN"));
        assert!(bundle.ends_with("-----END CERTIFICATE-----\n"));

        // No system bundle: the executor CA alone. Not a certificate: refused.
        let alone = combined_bundle(&[missing.as_path()], CA).expect("bundle");
        assert_eq!(alone.matches("-----BEGIN CERTIFICATE-----").count(), 1);
        assert!(combined_bundle(&[roots.as_path()], "not pem").is_err());
    }

    #[test]
    fn dotfiles_archives_are_written_by_plain_name_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("archives");
        let archive = DotfilesArchive {
            files: BTreeMap::from([
                ("manifest.json".to_owned(), "e30=".to_owned()),
                ("a.tar".to_owned(), "AAEC".to_owned()),
            ]),
        };
        write_dotfiles(&target, &archive).expect("written");
        assert_eq!(
            std::fs::read(target.join("manifest.json")).expect("manifest"),
            b"{}"
        );
        assert_eq!(std::fs::read(target.join("a.tar")).expect("a"), [0, 1, 2]);

        for bad in ["../escape", "a/b", "", ".."] {
            let archive = DotfilesArchive {
                files: BTreeMap::from([(bad.to_owned(), "AA==".to_owned())]),
            };
            assert!(write_dotfiles(&target, &archive).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_mode_is_read_from_the_kernel_command_line() {
        assert_eq!(
            mode_from_cmdline("console=hvc0 root=/dev/vda ro sealantd.mode=recover quiet\n"),
            Some(VmMode::Recover)
        );
        assert_eq!(
            mode_from_cmdline("root=/dev/vda sealantd.mode=normal"),
            Some(VmMode::Normal)
        );
        assert_eq!(mode_from_cmdline("root=/dev/vda ro"), None);
        assert_eq!(mode_from_cmdline("sealantd.mode=bogus"), None);
        assert_eq!(mode_from_cmdline("xsealantd.mode=recover"), None);
    }
}
