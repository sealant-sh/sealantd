//! A filter driver whose name is not UTF-8 still ran in a final flush's capture (review
//! 2026-09-28, sixth pass, #1). The capture emptied every driver the configuration defines, but
//! read their names lossily: `raw\xff` became `raw\u{fffd}`, a driver nobody defined, and the
//! user's `raw\xff` clean filter ran after the writers were stopped. It started a process that
//! wrote after the flush answered complete and sealed; the sealed head restored the bytes from
//! before. The overrides are the driver's bytes now, git is asked again under them to show no
//! driver is left, and a census before the seal finds any process alive.
//!
//! One test in its own binary on purpose: the sweep takes every descendant of the process it
//! runs in, as the daemon's does, and other tests' processes would be its descendants too.

mod support;

use std::io::Write;
use std::time::Duration;

use support::{EXECUTOR, boot, final_flush, restore};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_filter_driver_named_in_raw_bytes_never_runs_under_a_final_flush() {
    let tmp = tempfile::tempdir().unwrap();
    let (boot, registrar) = boot(tmp.path(), |store| store);
    let ws = tmp.path().join("ws");
    std::fs::write(ws.join("a-victim"), b"before filter\n").unwrap();
    std::fs::write(ws.join("z-trigger"), b"trigger\n").unwrap();
    std::fs::write(ws.join(".gitattributes"), b"z-trigger filter=raw\xff\n").unwrap();
    // The filter leaves a writer behind that waits for `release`, then writes the victim: the
    // test releases it once the flush answered.
    let release = tmp.path().join("release-writer");
    let script = tmp.path().join("filter.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n(sh -c 'while [ ! -f {} ]; do sleep .02; done; printf \"unique late \
             work\\n\" > {}' </dev/null >/dev/null 2>&1 &)\ncat\n",
            release.display(),
            ws.join("a-victim").display(),
        ),
    )
    .unwrap();
    let mut config = std::fs::OpenOptions::new()
        .append(true)
        .open(ws.join(".git/config"))
        .unwrap();
    config.write_all(b"\n[filter \"raw\xff\"]\n").unwrap();
    config
        .write_all(format!("\tclean = sh {}\n\trequired = true\n", script.display()).as_bytes())
        .unwrap();
    drop(config);

    let report = final_flush(&ws, boot).await;
    std::fs::write(&release, b"go").unwrap();
    // Long enough for a writer that was left running to have written.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        std::fs::read(ws.join("a-victim")).unwrap(),
        b"before filter\n",
        "the user's filter ran in a capture and left a writer behind"
    );
    assert!(report.complete, "{report:?}");
    let head = registrar.head().unwrap();
    assert!(
        head.manifest
            .final_seal
            .as_ref()
            .is_some_and(|seal| seal.executor == EXECUTOR),
        "the complete flush sealed its head"
    );
    let fresh = restore(tmp.path(), &registrar, "fresh");
    for name in ["a-victim", "z-trigger", ".gitattributes"] {
        assert_eq!(
            std::fs::read(fresh.join(name)).unwrap(),
            std::fs::read(ws.join(name)).unwrap(),
            "{name}: the sealed head is the disk"
        );
    }
}
