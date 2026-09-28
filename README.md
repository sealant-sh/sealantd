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
  `MERGE_HEAD`, a rebase, a cherry-pick sequence or a bisect names is in the packs — down to
  git's four-digit abbreviations. What an operation in progress needs to go on (a pending
  pseudo-ref, a todo list's `pick`-like operands, a rebase's `onto`) must resolve to exactly one
  object; one that is missing or ambiguous makes the final flush `snapshot-failed`, never
  complete. The working tree is read from disk past the user's index shortcuts: the scratch
  index drops `assume-unchanged`, and `skip-worktree` for every path on disk, and every git the
  capture runs has `core.ignorecase=false`, no fsmonitor, no untracked cache and full stat
  checks (`GIT_CONFIG_COUNT`); the user's `.git/index` and `.git/config` are never written.
- **A store that cannot hold what a capture holds.** When `plan.get`'s `manifest_features`
  leaves out one this daemon writes (`git_trees` above all), captures still ship, but no final
  flush is complete: `incomplete_reason: "store-fidelity"`, no seal. The executor is kept until
  a registrar that reads them recovers it.
- **Launch identity.** Core passes `SEALANT_CAPTURE_LAUNCH_ID` (the launch Mend minted and bound
  the session token to) in the boot environment. The first `plan.get` names it as `launch`
  (else the launch the disk last served, on a restart or a recovery boot); a plan answering
  another `executor` refuses the boot, and Mend refuses a `launch` that is not its token's (409
  `launch-mismatch`). A disk's staging continues the chain across an epoch change only for the
  launch that staged it. The daemon keeps presenting its own launch's token, a recovery boot's
  included.
- **Refusals that pause, never adopt.** `plan.get` 409 `worktree-leased` (another launch holds
  the lease; no epoch given, whatever `live_epoch` says): a boot waits (1 s, doubling to 30 s)
  and asks again, touching nothing; a re-plan keeps its identity. `upload.urls` and
  `capture.register` 409 `lease-lost`: shipping pauses with everything staged under its epoch.
  `lease.heartbeat` 404 (or 409) `lease-lost`: the harness pauses at once, and resumes when a
  heartbeat under the same identity succeeds.
- **The final seal** (`final_seal.executor`) is `plan.get`'s `executor`, the launch the session
  token was issued for, and nothing else. A plan that names no executor gets no seal.
- **`complete` means current.** `capture.status` says `complete` only while the disk is as the
  last final flush captured it. After any later change the watcher reports it answers
  `incomplete_reason: "changed"` until a final flush is asked again. While a class polls (a
  directory it could not watch, a watcher overflow) nothing can vouch for it after the flush:
  the status reads `"unwatched"`, and a final flush asked again snaps that class and answers
  complete. A final flush's own answer is complete when its snaps, taken after every writer
  stopped, captured every class, a polled one included.
- **The exit code follows the daemon's own last final flush.** A daemon exits 0 only when the
  last final flush it ran to its end answered complete, else 75; a final flush another request
  just began does not change that.
- **The shutdown's deadline: `SEALANT_SHUTDOWN_FINAL_DEADLINE_MS`.** The final flush of a
  shutdown (`SIGTERM`, `SIGINT`, `runtime.gracefulShutdown`) runs until it completes unless this
  is set. When it is set, the flush gets that many milliseconds from the moment the shutdown
  began: process grace, snaps and shipping included, and waiting for a final flush that is
  already running (a control plane's without a deadline, or the one after the harness exited).
  After that the daemon stops trying and exits 75 within about a second, its staging directory
  as it was. Nothing is lost: what is not registered is still staged on the disk, which the
  platform keeps and recovers (`--recovery`). **The platform sets it to its stop grace (the
  time between `SIGTERM` and `SIGKILL`) less a margin of at least 5 s**, so the daemon reports
  "not saved" itself instead of being killed mid-upload. A final flush after the harness exits
  on its own is not bounded by it, unless a shutdown begins meanwhile.
- **Uploads while the store or the registrar refuses.** A URL minted for a key is used again
  until that key's upload settles (stored, already there, or the URL refused) or it is five
  minutes old, and a multipart upload resumes under the same upload and part URLs. A pass that
  fails on a transient refusal (unreachable, 5xx, 429) is followed by a backoff of 1 s, doubling
  to 30 s, not by the next pass at once.
- **Watching.** A directory removed or renamed away before its watch is added (a dependency
  install's temporary directories) is not a failure. One that cannot be watched for a lasting
  reason (the watch limit, the budget, a permission) has its class poll, the rest of the class
  staying watched, and is tried again (2 s, doubling to 60 s): once it is watched, or gone, the
  class is watched again.
- **Remotes.** Plan remotes seed a base only: a repository built from an empty chain or from a
  capture without `.git/config` (Mend's capture 0) gets each one it lacks. A capture that carries
  `.git/config` is authoritative — a remote the user removed stays removed on a fresh executor —
  an existing URL is never changed, and a resumed or recovered disk is left as it is.
- **Which writers the final flush stops.** As PID 1 of its PID namespace (Docker, Kubernetes),
  every process in it. On a MicroVM the agent is PID 1 and passes `SEALANT_SWEEP_EXEMPT_FILE`, a
  JSON list it rewrites atomically as its helpers start and exit:
  `{"version":1,"exempt":[{"pid":212,"startTime":"5310","role":"dockerd","descendants":false}]}`
  (`startTime` is field 22 of `/proc/<pid>/stat`, a string or a number). The sweep then takes
  every process on the machine but sealantd, its ancestors, its own helpers and each listed
  process whose pid and start time both match a live one — with its descendants only when
  `descendants` is true. Nothing is spared by name. A stale entry spares nothing; a file that
  cannot be read or parsed makes the final flush `sweep-unavailable`. Without the file a daemon
  that is not PID 1 sweeps its own descendants, and a recovery boot there is always
  `sweep-unavailable` (the dead daemon's orphans were adopted by the agent). The workspace
  daemon's containers are stopped through the Engine API, which a restart policy does not undo.
- **Recovery reboot.** `sealantd boot --recovery` (or `SEALANT_RECOVERY=1`, or the marker
  `/.sealantd-recovery`) restarts a daemon that exited on its own disk, with the same boot
  environment and secret environment file. It never materializes over the disk and runs no
  dotfiles, lifecycle step or harness, and it admits nothing. It ships the disk's own staging,
  runs the final flush on its stop or when asked, and exits 0 only when that flush is complete,
  else 75. It resumes a disk whose staging continues the chain head, or one whose recorded
  materialize (capture id, executor, epoch) is exactly the head's; any other disk is refused,
  untouched — except a disk the daemon before it never materialized: the worktree absent, or
  holding nothing but `.sealantd/boot.lock` (empty) — no materialize record, no staging, no
  capture state, no repository, no file. Capture starts before any user code, so none ran there:
  the recovery exits **76** (`EX_PROTOCOL`, `EXIT_NOTHING_TO_SAVE`) with `nothing to save: never
  materialized` on stderr (log field `outcome="never-materialized"`), touching nothing and dialling
  nothing, and the platform may release that executor. Checked under the disk lock, before
  `plan.get`. Any other disk a recovery cannot save stays 75. One daemon runs per capture disk: every capture boot holds an exclusive lock on
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
