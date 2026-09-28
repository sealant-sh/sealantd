# sealantd

The authoritative runtime daemon that runs inside Sealant Linux workspaces. It records a
trustworthy factual record of an execution — process/PTY lifecycle, binary-safe I/O, filesystem
and network evidence — and exposes it over a versioned, length-prefixed **Protobuf** control
protocol (ADR-0012) on a Unix domain socket, consumed by a TypeScript SDK (and any language Buf can
generate). `sealantctl` is a debug client that speaks the same wire and prints JSON.

It is **not** a terminal emulator, an image builder, a Kubernetes scheduler, an SSH auth server, or
a semantic LLM engine. See `docs/runtime/known-limitations.md` for honest capability boundaries.

## Layout

```
crates/
  sealant-protocol/      typed commands, events, ids, versions, error codes (schema source of truth)
  sealant-runtime-core/  configuration, state machines, policy, health
  sealant-process/       exec, registry, process groups, pidfds, reaping
  sealant-pty/           PTY allocation, sessions, input/output, resize
  sealant-telemetry/     event bus, sequencing, priority, batching, sinks
  sealant-eventlog/      append-only spool, checksums, recovery, rotation
  sealant-fs/            snapshots, hashing, inotify watcher, coalescing, diffs
  sealant-network/       explicit egress proxy, capability detection, source normalization
  sealant-control/       Unix socket, stdio adapter, framing, peer validation, dispatch
  sealantd/              binary composition and lifecycle
  sealantctl/            debug and integration-test client
packages/
  runtime-protocol/      generated/contract-checked TypeScript types (@sealant/runtime-protocol)
  runtime-client/        ergonomic TypeScript SDK client (@sealant/runtime-client)
  fuzz/                  cargo-fuzz targets for the control-protocol decoders
docs/
  runtime/               requirements matrix, architecture, operations, benchmarks, threat model
  adr/                   architecture decision records
```

## Status

Phases 0–8 complete (plan §22): protocol, process/PTY runtime, telemetry + durable spool,
filesystem and network telemetry, security hardening, and packaging. Tracked phase-by-phase in
`docs/runtime/requirements-matrix.md`.

## Runs as root

`sealantd boot` runs as root (uid 0), as PID 1 of the workspace's PID namespace in Docker and
Kubernetes: it creates `/root` and runs the harness with `HOME=/root` (dotfiles are applied
there), its final capture's sweep terminates every process in the namespace whoever owns it, and
it writes `fs.inotify.max_user_watches` when `SEALANT_CAPTURE_INOTIFY_RAISE` asks. Another user is
not supported. What such a daemon would need, and how far it gets today: the workspace root and
working directory writable by it (the volume the orchestrator mounts; a restore that cannot write
names the path it could not), the control socket's directory (`SEALANT_CONTROL_SOCKET`, default
`/run/sealant/control.sock`) and `/run/sealant` writable, and a session journal directory —
`SEALANT_SESSION_JOURNAL_DIR`, else `$XDG_STATE_HOME/sealantd/session-journals`, else
`$HOME/.local/state/sealantd/session-journals` (root's default, `/var/lib/sealantd/…`, is not
one it can create). The harness's `HOME` stays `/root`.

## Capture store: what Core and Mend rely on

A capture-source workspace (`SEALANT_WORKSPACE_SOURCE=capture`, ADR-0015) keeps its work product
in the control plane's store. The contracts below are the ones the control plane builds against;
the protocol details live in `crates/sealant-capture/src/registrar.rs` and `manifest.rs`.

- **Capture starts before user code.** The engine starts right after the head is materialized,
  before dotfiles, lifecycle setup/startup steps and the harness. Every exit after that runs the
  final flush, and a daemon whose final flush is incomplete exits 75 (`EX_TEMPFAIL`), whatever
  failed.
- **Object keys** are `captures/<worktree>/<epoch>/g<generation>/{packs,trees,manifests}/<sha256>`.
  The generation starts at 0 per worktree and epoch and moves on, durably, before every rebuild
  of a capture the registrar refused. A key a register was refused for is never written again:
  what the rebuild uploads, even the same bytes, goes up under the next generation. A key without
  the `g<n>` segment was written before generations and is read as before.
- **The git section** (`git_trees` manifest feature, written only when `plan.get` lists it)
  names `worktree_tree` (the working tree as `git add -A` stages it: what a review diffs),
  `index_tree` and `raw_tree` in their own fields. `raw_tree` holds every file's bytes as they are
  on disk, before any clean filter, end-of-line or `working-tree-encoding` conversion; a restore
  checks it out and writes those bytes back unsmudged. `refs` is then the repository's refs,
  whatever their names. Without the feature the two trees ride `refs` as
  `refs/sealant/capture/worktree` and `…/index`, as before. `HEAD` is its immediate target (a
  symbolic ref chain is kept link by link), and every object `FETCH_HEAD`, `ORIG_HEAD`,
  `MERGE_HEAD`, a rebase, a cherry-pick sequence or a bisect names is in the packs.
- **The final seal** (`final_seal.executor`) is `plan.get`'s `executor`, the launch the session
  token was issued for, and nothing else. A plan that names no executor gets no seal.
- **`complete` means current.** `capture.status` and the final flush's answer say `complete`
  only while the disk is as the last final flush captured it. After any later change the watcher
  reports, or a watcher overflow, they answer `incomplete_reason: "changed"` until a final flush
  is asked again.
- **Remotes.** Plan remotes are added only where the repository has no remote of that name. An
  existing URL is never changed, and a resumed or recovered disk is left as it is.
- **Recovery reboot.** `sealantd boot --recovery` (or `SEALANT_RECOVERY=1`, or the marker
  `/.sealantd-recovery`) restarts a daemon that exited on its own disk, with the same boot
  environment and secret environment file. It never materializes over the disk and runs no
  dotfiles, lifecycle step or harness, and it admits nothing. It ships the disk's own staging,
  runs the final flush on its stop or when asked, and exits 0 only when that flush is complete,
  else 75. It resumes a disk whose staging continues the chain head, or one whose recorded
  materialize (capture id, executor, epoch) is exactly the head's; any other disk is refused,
  untouched. One daemon runs per capture disk: every capture boot holds an exclusive lock on
  `<worktree>/.sealantd/boot.lock`, and a second boot beside a live one exits 75 without touching
  anything. On a still-running MicroVM, Core's agent stops every process the dead daemon left,
  then spawns `sealantd boot --recovery` exactly as it spawned `sealantd boot`.

## Build & validate

```
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
examples/demo.sh                                      # end-to-end: run a command through the daemon
scripts/build-release.sh                              # static musl binaries -> dist/ (amd64 + arm64)
```

Target is Linux-first (pidfd, inotify, PTY ctty, `SO_PEERCRED`). The dev host may be macOS;
Linux-only behaviors are validated inside docker containers (`scripts/linux-test.sh`). See
`docs/runtime/operations.md` to run and deploy, and `docs/runtime/benchmarks.md` for measurements.
