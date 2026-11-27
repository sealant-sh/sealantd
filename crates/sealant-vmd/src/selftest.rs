//! `sealant-vmd --self-test` and `GET /v1/self-test`.

use std::path::Path;
#[cfg(target_os = "macos")]
use std::process::Command;

use sealant_vmm_proto::{SelfTestCheck, SelfTestReport};
use serde_json::{Map, Value, json};

use crate::sys;

/// Minimum supported macOS major release for native Apple Silicon `host-vm`.
pub const MIN_MACOS_MAJOR: u32 = 14;

/// Runs all host readiness checks and returns a report matching `sealant-vm-runner --self-test`.
pub fn run(kernel: &Path, worker: &Path, vm_root: &Path) -> SelfTestReport {
    let checks = vec![
        check_apple_silicon(),
        check_macos_version(),
        check_worker_binary(worker),
        check_kernel(kernel),
        check_sparse_storage(vm_root),
        check_launchd_domain(),
    ];
    SelfTestReport {
        version: 1,
        ok: checks.iter().all(|c| c.ok),
        checks,
    }
}

fn make_check(name: &str, ok: bool, observed: impl Into<String>, facts: Value) -> SelfTestCheck {
    SelfTestCheck {
        name: name.to_owned(),
        ok,
        observed: observed.into(),
        facts: match facts {
            Value::Object(map) => map,
            _ => Map::new(),
        },
    }
}

fn check_apple_silicon() -> SelfTestCheck {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let ok = os == "macos" && arch == "aarch64";
    let observed = if ok {
        "Apple Silicon macOS (arm64)".to_owned()
    } else {
        format!("unsupported host {os}/{arch} (requires macos/aarch64)")
    };
    make_check(
        "appleSilicon",
        ok,
        observed,
        json!({ "os": os, "arch": arch }),
    )
}

fn check_macos_version() -> SelfTestCheck {
    let version = sys::macos_version_string();
    let major = version
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok());
    let ok = cfg!(target_os = "macos") && major.is_some_and(|m| m >= MIN_MACOS_MAJOR);
    let observed = if ok {
        format!("macOS {version} (>= {MIN_MACOS_MAJOR}.0)")
    } else {
        format!("OS version {version:?} does not meet macOS {MIN_MACOS_MAJOR}.0+")
    };
    make_check(
        "macosVersion",
        ok,
        observed,
        json!({ "version": version, "requiredMajor": MIN_MACOS_MAJOR }),
    )
}

fn check_worker_binary(worker: &Path) -> SelfTestCheck {
    let path = worker.display().to_string();
    if !worker.is_file() {
        return make_check(
            "vzWorkerSigned",
            false,
            format!("{path} is missing"),
            json!({ "path": path }),
        );
    }
    #[cfg(target_os = "macos")]
    {
        #[allow(
            clippy::disallowed_methods,
            reason = "sealant-vmd is a standalone macOS daemon with no orphan reaper"
        )]
        let output = Command::new("/usr/bin/codesign")
            .args(["-d", "--entitlements", ":-"])
            .arg(worker)
            .output();
        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                let has_virt = text.contains("com.apple.security.virtualization");
                let observed = if has_virt {
                    format!("{path} carries com.apple.security.virtualization")
                } else {
                    format!("{path} is missing com.apple.security.virtualization entitlement")
                };
                make_check(
                    "vzWorkerSigned",
                    has_virt,
                    observed,
                    json!({ "path": path, "hasVirtualizationEntitlement": has_virt }),
                )
            }
            Ok(out) => make_check(
                "vzWorkerSigned",
                false,
                format!(
                    "codesign failed for {path}: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
                json!({ "path": path }),
            ),
            Err(e) => make_check(
                "vzWorkerSigned",
                false,
                format!("cannot invoke codesign: {e}"),
                json!({ "path": path }),
            ),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        make_check(
            "vzWorkerSigned",
            false,
            format!("codesign entitlement verification requires macOS ({path})"),
            json!({ "path": path }),
        )
    }
}

fn check_kernel(kernel: &Path) -> SelfTestCheck {
    let path = kernel.display().to_string();
    match std::fs::metadata(kernel) {
        Ok(meta) if meta.is_file() && meta.len() > 0 => make_check(
            "kernelPresent",
            true,
            format!("{path} ({} bytes)", meta.len()),
            json!({ "path": path, "bytes": meta.len() }),
        ),
        Ok(_) => make_check(
            "kernelPresent",
            false,
            format!("{path} is empty or not a regular file"),
            json!({ "path": path }),
        ),
        Err(e) => make_check(
            "kernelPresent",
            false,
            format!("{path} unavailable: {e}"),
            json!({ "path": path }),
        ),
    }
}

fn check_sparse_storage(vm_root: &Path) -> SelfTestCheck {
    let path = vm_root.display().to_string();
    let available = sys::disk_available_bytes(vm_root);
    let ok = vm_root.is_dir() && available > 0;
    let observed = if ok {
        format!("{path} accessible ({available} bytes available)")
    } else {
        format!("{path} missing or unavailable")
    };
    make_check(
        "apfsSparse",
        ok,
        observed,
        json!({ "path": path, "availableBytes": available }),
    )
}

fn check_launchd_domain() -> SelfTestCheck {
    #[cfg(target_os = "macos")]
    {
        let domain = format!("gui/{}", sys::current_uid());
        #[allow(
            clippy::disallowed_methods,
            reason = "sealant-vmd is a standalone macOS daemon with no orphan reaper"
        )]
        let ok = Command::new("/bin/launchctl")
            .args(["print", &domain])
            .output()
            .is_ok_and(|o| o.status.success());
        let observed = if ok {
            format!("launchd domain {domain} is active")
        } else {
            format!(
                "launchd domain {domain} is inactive (headless SSH-only sessions cannot run GUI LaunchAgents)"
            )
        };
        make_check(
            "launchAgentDomain",
            ok,
            observed,
            json!({ "domain": domain }),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        make_check(
            "launchAgentDomain",
            false,
            "launchd domain check requires macOS",
            json!({}),
        )
    }
}
