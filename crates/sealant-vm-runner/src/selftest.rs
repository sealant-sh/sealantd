//! `sealant-vm-runner --self-test` (§9.1): what `mend server setup` runs, in a container started
//! with the same devices and capabilities as a real workspace, to report what it observed.
//!
//! One JSON object on stdout: `{"version":1,"ok":bool,"checks":[...]}`, each check with its
//! `name`, `ok`, an `observed` sentence and the raw facts it was judged on. Every check runs even
//! when an earlier one fails, so the report names every missing piece at once.

use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::sys;

/// The Cloud Hypervisor release the runner's flags are verified against.
pub const CLOUD_HYPERVISOR_MAJOR: u32 = 54;
/// `KVM_GET_API_VERSION` has answered 12 since Linux 2.6.22.
const KVM_API_VERSION: i32 = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probes {
    pub kvm: PathBuf,
    pub tun: PathBuf,
    pub nft: String,
    pub cloud_hypervisor: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub version: u32,
    pub ok: bool,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub observed: String,
    #[serde(flatten)]
    pub facts: Map<String, Value>,
}

impl Check {
    fn new(name: &'static str, ok: bool, observed: impl Into<String>, facts: Value) -> Self {
        Self {
            name,
            ok,
            observed: observed.into(),
            facts: match facts {
                Value::Object(map) => map,
                _ => Map::new(),
            },
        }
    }
}

pub fn run(probes: &Probes) -> Report {
    let checks = vec![
        check_kvm(&probes.kvm),
        check_tun(&probes.tun),
        check_nft(&probes.nft),
        check_landlock(),
        check_cloud_hypervisor(&probes.cloud_hypervisor),
    ];
    Report {
        version: 1,
        ok: checks.iter().all(|c| c.ok),
        checks,
    }
}

fn check_kvm(path: &Path) -> Check {
    let shown = path.display().to_string();
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return Check::new(
                "kvm",
                false,
                format!("{shown} unavailable: {e}"),
                json!({ "path": shown }),
            );
        }
    };
    let gid = meta.gid();
    let mode = format!("{:04o}", meta.mode() & 0o7777);
    let mut facts = json!({ "path": shown, "gid": gid, "mode": mode });
    if !meta.file_type().is_char_device() {
        return Check::new(
            "kvm",
            false,
            format!("{shown} is not a character device"),
            facts,
        );
    }
    let api = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .and_then(|f| sys::kvm_api_version(f.as_fd()));
    match api {
        Ok(version) => {
            facts["apiVersion"] = json!(version);
            let mut problems = Vec::new();
            if version != KVM_API_VERSION {
                problems.push(format!("KVM API {version}, expected {KVM_API_VERSION}"));
            }
            if gid == 0 {
                problems.push(
                    "owned by group 0 (the runner refuses to keep root's group; pass --kvm-gid)"
                        .to_owned(),
                );
            }
            let ok = problems.is_empty();
            let observed = if ok {
                format!("{shown} opened read-write, KVM API {version}, group {gid}, mode {mode}")
            } else {
                format!("{shown}: {}", problems.join("; "))
            };
            Check::new("kvm", ok, observed, facts)
        }
        Err(e) => Check::new(
            "kvm",
            false,
            format!("{shown} (group {gid}, mode {mode}) cannot be opened read-write: {e}"),
            facts,
        ),
    }
}

fn check_tun(path: &Path) -> Check {
    let shown = path.display().to_string();
    let facts = json!({ "path": shown });
    match std::fs::metadata(path) {
        Ok(m) if !m.file_type().is_char_device() => {
            return Check::new(
                "tun",
                false,
                format!("{shown} is not a character device"),
                facts,
            );
        }
        Err(e) => return Check::new("tun", false, format!("{shown} unavailable: {e}"), facts),
        Ok(_) => {}
    }
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(_) => Check::new("tun", true, format!("{shown} opened read-write"), facts),
        Err(e) => Check::new(
            "tun",
            false,
            format!("{shown} cannot be opened read-write: {e}"),
            facts,
        ),
    }
}

fn check_nft(nft: &str) -> Check {
    let version = match crate::nft::run(nft, &["--version"], None) {
        Ok(out) => out.trim().to_owned(),
        Err(e) => {
            return Check::new("nftables", false, format!("{e}"), json!({ "binary": nft }));
        }
    };
    let table = format!("sealant_selftest_{}", std::process::id());
    let mut facts = json!({ "binary": nft, "version": version, "table": table });
    let created = crate::nft::apply(
        nft,
        &format!(
            "table inet {table} {{\n\tchain forward {{\n\t\ttype filter hook forward priority 0; policy accept;\n\t}}\n}}\n"
        ),
    );
    if let Err(e) = created {
        return Check::new(
            "nftables",
            false,
            format!("{version}, but a test table could not be created in this netns: {e}"),
            facts,
        );
    }
    let listed = crate::nft::run(nft, &["list", "table", "inet", &table], None);
    let deleted = crate::nft::run(nft, &["delete", "table", "inet", &table], None);
    facts["listed"] = json!(listed.is_ok());
    facts["deleted"] = json!(deleted.is_ok());
    match (listed, deleted) {
        (Ok(_), Ok(_)) => Check::new(
            "nftables",
            true,
            format!("{version}; created, listed and deleted a test table in this netns"),
            facts,
        ),
        (listed, deleted) => {
            let err = listed.err().or(deleted.err()).map(|e| e.to_string());
            Check::new(
                "nftables",
                false,
                format!(
                    "{version}; test table created but not listed and deleted cleanly: {}",
                    err.unwrap_or_default()
                ),
                facts,
            )
        }
    }
}

fn check_landlock() -> Check {
    match sys::landlock_abi_version() {
        Ok(abi) => Check::new(
            "landlock",
            abi >= 1,
            format!("Landlock ABI {abi}"),
            json!({ "abi": abi }),
        ),
        Err(e) => Check::new(
            "landlock",
            false,
            format!("Landlock unavailable: {e}"),
            json!({ "abi": null }),
        ),
    }
}

fn check_cloud_hypervisor(binary: &Path) -> Check {
    let shown = binary.display().to_string();
    #[allow(
        clippy::disallowed_methods,
        reason = "the runner is its own binary with no orphan reaper, which is what the spawn gate protects against; the gate would also close the TAP descriptor the VMM must inherit"
    )]
    let output = match Command::new(binary).arg("--version").output() {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            return Check::new(
                "cloudHypervisor",
                false,
                format!("{shown} --version failed ({})", o.status),
                json!({ "binary": shown }),
            );
        }
        Err(e) => {
            return Check::new(
                "cloudHypervisor",
                false,
                format!("{shown} cannot run: {e}"),
                json!({ "binary": shown }),
            );
        }
    };
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let major = parse_major(&version);
    let facts = json!({ "binary": shown, "version": version, "major": major });
    match major {
        Some(CLOUD_HYPERVISOR_MAJOR) => Check::new("cloudHypervisor", true, version, facts),
        Some(m) => Check::new(
            "cloudHypervisor",
            false,
            format!("{version}: major {m}, expected {CLOUD_HYPERVISOR_MAJOR}"),
            facts,
        ),
        None => Check::new(
            "cloudHypervisor",
            false,
            format!("unrecognised version output {version:?}"),
            facts,
        ),
    }
}

/// `cloud-hypervisor v54.0.0` (or `v54.0-dirty`) → 54.
fn parse_major(version: &str) -> Option<u32> {
    let token = version.split_whitespace().find(|t| {
        t.strip_prefix('v')
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
    })?;
    token[1..]
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn check<'a>(report: &'a Report, name: &str) -> &'a Check {
        report.checks.iter().find(|c| c.name == name).unwrap()
    }

    #[test]
    fn the_report_names_each_missing_piece_and_is_not_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let regular = tmp.path().join("kvm");
        std::fs::write(&regular, "").unwrap();
        // An nft that knows its version but may not touch this netns, and a VMM a release behind.
        let nft = script(
            tmp.path(),
            "nft",
            r#"if [ "$1" = --version ]; then echo "nftables v1.1.1 (Commodore Bullmoose #2)"; else echo "Operation not permitted" >&2; exit 1; fi"#,
        );
        let ch = script(
            tmp.path(),
            "cloud-hypervisor",
            "echo cloud-hypervisor v53.1.0",
        );
        let report = run(&Probes {
            kvm: regular,
            tun: tmp.path().join("missing-tun"),
            nft: nft.display().to_string(),
            cloud_hypervisor: ch,
        });
        assert!(!report.ok);
        let kvm = check(&report, "kvm");
        assert!(
            !kvm.ok && kvm.observed.contains("not a character device"),
            "{kvm:?}"
        );
        let tun = check(&report, "tun");
        assert!(!tun.ok && tun.observed.contains("unavailable"), "{tun:?}");
        let nft = check(&report, "nftables");
        assert!(
            !nft.ok && nft.observed.contains("Operation not permitted"),
            "{nft:?}"
        );
        assert_eq!(
            nft.facts["version"],
            "nftables v1.1.1 (Commodore Bullmoose #2)"
        );
        let ch = check(&report, "cloudHypervisor");
        assert!(!ch.ok && ch.observed.contains("expected 54"), "{ch:?}");
        assert_eq!(ch.facts["major"], 53);

        let json: Value = serde_json::to_value(&report).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["ok"], false);
        assert_eq!(json["checks"].as_array().unwrap().len(), 5);
        assert!(json["checks"][0].get("observed").is_some());
    }

    #[test]
    fn a_working_nft_and_vmm_pass_their_checks() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("nft.log");
        // Records each invocation (and the batch it was fed) so the test sees the table come and
        // go.
        let nft = script(
            tmp.path(),
            "nft",
            &format!(
                r#"echo "$@" >> {log}; if [ "$1" = -f ]; then cat >> {log}; fi; if [ "$1" = --version ]; then echo "nftables v1.1.1"; fi"#,
                log = log.display()
            ),
        );
        let ch = script(
            tmp.path(),
            "cloud-hypervisor",
            "echo cloud-hypervisor v54.0.0",
        );
        let report = run(&Probes {
            kvm: tmp.path().join("no-kvm"),
            tun: tmp.path().join("no-tun"),
            nft: nft.display().to_string(),
            cloud_hypervisor: ch,
        });
        let nft_check = check(&report, "nftables");
        assert!(nft_check.ok, "{nft_check:?}");
        let calls = std::fs::read_to_string(&log).unwrap();
        let table = format!("sealant_selftest_{}", std::process::id());
        assert!(calls.contains(&format!("table inet {table} {{")), "{calls}");
        assert!(
            calls.contains(&format!("list table inet {table}")),
            "{calls}"
        );
        assert!(
            calls.contains(&format!("delete table inet {table}")),
            "{calls}"
        );
        assert!(check(&report, "cloudHypervisor").ok);
        assert!(!report.ok, "kvm and tun are missing");
    }

    #[test]
    fn version_majors() {
        assert_eq!(parse_major("cloud-hypervisor v54.0.0"), Some(54));
        assert_eq!(parse_major("cloud-hypervisor v54.0-dirty"), Some(54));
        assert_eq!(parse_major("cloud-hypervisor 54"), None);
        assert_eq!(parse_major(""), None);
    }
}
