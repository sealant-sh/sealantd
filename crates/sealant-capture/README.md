# sealant-capture

> Status (PR sealantd#71): the cadence is watcher-fed. The small class snaps 2 s after the last
> change and at most every 10 s while dirty; the bulk class has its own 30 s / 120 s clocks and
> yields to small snaps at chunk boundaries; turn boundaries, checkpoints, `capture.flush` and the
> SIGTERM/SIGINT/`gracefulShutdown` paths force a small snap ahead of the timers. Watch budget not
> met, `IN_Q_OVERFLOW` or no backend → that class polls at its maximum interval (the stat walk).
> Still open: the registrar wire shape is provisional (`registrar.rs`).

The executor-side half of the session capture store (ADR-0015). A workspace is captured as two
classes of content-addressed objects in a bucket-shaped `BlobSink`: git objects as self-contained
git packs (`gitpack`), everything else as content-defined chunks in CDC packs (`chunk`, `pack`)
described by dir objects (`tree`). A `Manifest` ties one capture together; `ship` stages, uploads
and registers it through a `Registrar`; `materialize` rebuilds a workspace from a manifest.
`CaptureEngine` is the front door: `snap(class, kind)` stages a capture, `snap_preemptible` lets a
bulk build yield.

## Cadence (`cadence.rs`, `watch.rs`)

`CadenceRunner` owns the engine and two clocks. `watch.rs` runs the `sealant-fs` pruned
per-directory inotify watcher over the capture roots (the worktree minus bulk directories, the
git dir, the harness home; bulk directories separately) under the capture ignore policy and marks
a class dirty on every create/modify/remove. Small class: `quiet` (2 s) after the last change,
`max_interval` (10 s) from the first; bulk class: `bulk_quiet` (30 s) / `bulk_max_interval`
(120 s), one bulk snap in flight, resumed after every yield without re-reading. Forced snaps
(`CadenceRunner::snap`, `flush`) preempt a bulk build. Directories are counted before watching;
over budget (half the sysctl, or `WatchPolicy::budget`) the class polls; `raise_limit` tries the
sysctl first and never fails boot. `tests/cadence.rs` measures all of it against the real watcher.
