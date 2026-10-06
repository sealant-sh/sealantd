//! Measure what the worktree metadata overlay adds to a small snap on a real repository: the
//! `git ls-tree` of the tree, the lstat of every path it names, the directory walk (with its
//! `git ls-files` of ignored directories), the encode and the chunking.
//!
//! `cargo run --release --example overlay_cost -- <root> [iterations]`
//!
//! Read-only: the tree measured is `HEAD^{tree}` (the worktree tree of a clean checkout), so
//! nothing is written to the repository.

use std::time::{Duration, Instant};

use sealant_capture::chunk::chunk_bytes;
use sealant_capture::gitpack::GitRepo;
use sealant_capture::index::{DAEMON_DIR, DEFAULT_BULK_DIRS};
use sealant_capture::pack::compress_chunk;
use sealant_capture::worktree_meta::{self, MetaScope};

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i]
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = std::path::PathBuf::from(args.first().expect("root"));
    let iterations: usize = args.get(1).map_or(20, |n| n.parse().expect("iterations"));
    let repo = GitRepo::open(&root).expect("repository");
    let tree = String::from_utf8(
        repo.run(&["rev-parse", "HEAD^{tree}"])
            .expect("tree")
            .stdout,
    )
    .expect("utf-8")
    .trim()
    .to_owned();
    let scope = MetaScope {
        root: root.clone(),
        excludes: vec![DAEMON_DIR.to_owned()],
        bulk_dirs: DEFAULT_BULK_DIRS.iter().map(|s| (*s).to_owned()).collect(),
        nested: repo.nested_repositories(None).expect("nested"),
        skip_abs: Vec::new(),
        shared_group: false,
    };
    let mut times = Vec::with_capacity(iterations);
    let mut last = None;
    for _ in 0..iterations {
        let start = Instant::now();
        let captured = worktree_meta::capture(&repo, &tree, &scope, None).expect("capture");
        let bytes = captured.doc.encode();
        let chunks = chunk_bytes(&bytes);
        times.push(start.elapsed());
        last = Some((captured.doc, bytes.len(), chunks.len()));
    }
    times.sort();
    let (mut doc, bytes, chunks) = last.expect("one iteration");
    // One file's mtime moves: what the next capture uploads for the overlay (new chunks,
    // compressed as packs store them).
    let before: std::collections::HashSet<_> = chunk_bytes(&doc.encode())
        .into_iter()
        .map(|c| c.id)
        .collect();
    if let Some(e) = doc
        .entries
        .iter_mut()
        .find(|e| e.kind == worktree_meta::MetaKind::File)
    {
        e.mtime += 1;
    }
    let new: Vec<_> = chunk_bytes(&doc.encode())
        .into_iter()
        .filter(|c| !before.contains(&c.id))
        .collect();
    let new_bytes: usize = new
        .iter()
        .map(|c| compress_chunk(&c.data).expect("zstd").len())
        .sum();
    let whole: usize = chunk_bytes(&doc.encode())
        .iter()
        .map(|c| compress_chunk(&c.data).expect("zstd").len())
        .sum();
    let dirs = doc
        .entries
        .iter()
        .filter(|e| e.kind == worktree_meta::MetaKind::Dir)
        .count();
    println!(
        "{}: {} entries ({} directories), document {} bytes in {} chunks; {} runs: p50 {:.1} ms, p90 {:.1} ms, max {:.1} ms",
        root.display(),
        doc.entries.len(),
        dirs,
        bytes,
        chunks,
        iterations,
        percentile(&times, 0.5).as_secs_f64() * 1e3,
        percentile(&times, 0.9).as_secs_f64() * 1e3,
        times.last().copied().unwrap_or_default().as_secs_f64() * 1e3,
    );
    println!(
        "  compressed document {whole} bytes; one mtime changed: {} new chunk(s), {new_bytes} bytes compressed to upload",
        new.len()
    );
}
