//! The platform key names the workspace's userland, not sealantd's build. sealantd is a static
//! musl binary; keyed by its build it said `linux-x86_64-musl` in every glibc workspace while
//! Mend's probe (`uname -s; uname -m; ldd --version`) said `-gnu`, so every resume answered the
//! head's dependency tree `"pending"` and installed it again (Docker end to end, 2026-09-27).

use std::fs;
use std::path::Path;

use sealant_capture::engine::{default_platform, platform_of};

fn host(libc: &str) -> String {
    format!("{}-{}-{libc}", std::env::consts::OS, std::env::consts::ARCH)
}

#[test]
fn a_glibc_userland_is_gnu_whatever_the_build() {
    if std::env::consts::OS != "linux" {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("lib64")).unwrap();
    fs::write(root.path().join("lib64/ld-linux-x86-64.so.2"), b"").unwrap();
    let glibc = || Some("ldd (GNU libc) 2.39\nCopyright (C) 2024\n".to_owned());
    assert_eq!(platform_of(root.path(), glibc), host("gnu"));
    // No `ldd` at all (a distroless image): Mend's probe says gnu too.
    assert_eq!(platform_of(root.path(), || None), host("gnu"));
}

#[test]
fn a_musl_userland_is_musl() {
    if std::env::consts::OS != "linux" {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("lib")).unwrap();
    fs::write(root.path().join("lib/ld-musl-x86_64.so.1"), b"").unwrap();
    assert_eq!(
        platform_of(root.path(), || panic!(
            "the loader decides; ldd is not asked"
        )),
        host("musl")
    );
    // No loader where it is looked for, but `ldd --version` (musl prints it on stderr) says so.
    let bare = tempfile::tempdir().unwrap();
    let musl = || Some("musl libc (x86_64)\nVersion 1.2.5\n".to_owned());
    assert_eq!(platform_of(bare.path(), musl), host("musl"));
}

/// This process's key is the detection over `/`, the same one `plan.get` and the bulk class use.
#[test]
fn the_daemon_key_is_the_userland_of_its_root() {
    let expected = platform_of(Path::new("/"), || {
        std::process::Command::new("ldd")
            .arg("--version")
            .output()
            .ok()
            .map(|o| {
                let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
                s.push_str(&String::from_utf8_lossy(&o.stderr));
                s
            })
    });
    assert_eq!(default_platform(), expected);
}
