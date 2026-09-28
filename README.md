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
  checks it out and writes those bytes back unsmudged. Every regular file is hashed raw (`git
  hash-object --no-filters`, cached by stat), not only the ones an attribute file among the index
  entries seems to name: git also reads a `.gitattributes` the index does not hold, an ignored
  one included, and a CRLF file under such a `*.txt text` was sealed and restored as LF.
  `refs` is then the repository's refs,
  whatever their names. Without the feature the two trees ride `refs` as
  `refs/sealant/capture/worktree` and `…/index`, as before. `HEAD` is its immediate target (a
  symbolic ref chain is kept link by link). A symbolic ref or `HEAD` stored as a symlink
  (`core.preferSymlinkRefs`) is kept as a symbolic ref — name and target bytes, dangling and
  chained — and as the symlink it was, its link text and mtime riding the workspace class. The
  `.git` directory and the harness home keep their mode and nanosecond mtime. A `.git` or a
  harness home that is a symlink to a directory is read through the link, as git and the harness
  read it (the link text rides `workspace.root_links`; a restore writes the directory it named),
  and one that is not a directory at all (a file, a link to one, a loop) makes a final flush
  `unreadable` — before, either was captured as nothing and the flush still sealed. Every object `FETCH_HEAD`, `ORIG_HEAD`,
  `MERGE_HEAD`, a rebase, a cherry-pick sequence or a bisect names is in the packs — down to
  git's four-digit abbreviations, and through a symlinked pseudo-ref or operation document, read
  as git reads it; one that cannot be read makes the final flush `snapshot-failed`. A symlink
  with more than one name (a hardlinked symlink, `cp -al`) cannot come back as one inode: a final
  flush over one is `snapshot-failed`. A SHA-256 repository is captured and restored as one (the
  git section's `object_format`, a manifest feature; a store that does not read it gets no
  complete final flush of a SHA-256 repository). `HEAD`, the refs, the reflogs and the root refs
  (`ORIG_HEAD`, `CHERRY_PICK_HEAD`, …) are read through git in whichever backend holds them,
  never through `.git/HEAD` or a `logs/` directory: a reftable repository's `HEAD` file only says
  `ref: refs/heads/.invalid` and it has no `logs/`, and a commit only its reflog, a detached
  `HEAD` or its `ORIG_HEAD` reached was left out of a sealed capture. A reftable repository is
  captured and restored as one (the git section's `ref_format: "reftable"`, a manifest feature;
  the restore runs `git init --ref-format=reftable` and writes the refs through `update-ref` and
  `symbolic-ref`, and the workspace class brings the tables themselves back, reflogs included; a
  store that does not read `ref_format` gets no complete final flush of a reftable repository).
  Every symlink under `.git/refs/` or at `.git/HEAD` rides the workspace class as the symlink it
  was, whatever its link text: an alias git reads through to another ref's file
  (`refs/heads/alias -> main`) comes back as that symlink, and the restore writes the ref file it
  reaches loose again so it still resolves (the git section packs every ref). One whose chain
  ends where a restore cannot bring a file back (outside the repository, on no ref the capture
  holds) makes a final flush `snapshot-failed`. Every object a reflog names is packed, whatever
  its type: a blob, a tree or an annotated tag a ref was moved away from (a notes or custom ref, a
  tag) was left out, because `git rev-list --reflog` lists commits only, and a sealed capture
  restored a reflog naming objects the repository did not hold. A nested repository that shares
  git storage with the top-level one is captured with what it needs: a linked worktree inside the
  workspace (`git worktree add <workspace>/child`) keeps its administrative directory
  (`.git/worktrees/<name>`: its `index`, `HEAD`, `ORIG_HEAD`, reflog and per-worktree refs, in the
  workspace class), and its `HEAD`, refs, reflogs, every index stage and operation state join
  the top-level closure; a nested repository whose `objects/info/alternates` (or common
  directory) is the top-level object store gets the objects its own state reaches there packed
  beside the closure. A nested repository whose git directory, common directory or alternates
  live outside the workspace cannot come back from a capture of it: a final flush over one is
  `snapshot-failed`, naming it (an automatic capture ships all the same); one under a bulk
  directory that borrows the top-level store is refused the same way. What an operation in progress needs to go on (a pending
  pseudo-ref, a todo list's `pick`-like operands, a rebase's `onto`) must resolve to exactly one
  object; one that is missing or ambiguous makes the final flush `snapshot-failed`, never
  complete. The working tree is read from disk past the user's index shortcuts: the scratch
  index drops `assume-unchanged`, and `skip-worktree` for every path on disk, and every git the
  capture runs has `core.ignorecase=false`, no fsmonitor, no untracked cache and full stat
  checks (`GIT_CONFIG_COUNT`); the user's `.git/index` and `.git/config` are never written.
- **A capture runs none of the user's code.** Every git a capture runs has each filter driver the
  configuration defines emptied (`filter.<driver>.clean`, `.smudge`, `.process` empty,
  `.required=false`), `core.hooksPath=/dev/null` (no `post-index-change` hook), no fsmonitor,
  `core.symlinks=true` and `core.safecrlf=false`. A driver's name is its bytes (a subsection name
  need not be UTF-8: read lossily, `raw\xff` became another driver and the user's still ran), and
  git is asked again under the overrides: a driver left with a command or `required` on, or a
  configuration that cannot be read, fails the git before it runs (a final flush over it is
  `snapshot-failed`). A final flush also takes a census before it seals: a descendant of the
  daemon alive after the writers stopped (what a git of the capture's would have started: every
  orphan of the daemon's comes back to it; its own gated `git` is spared) is killed and the
  classes are snapped again; one found on the last of three rounds answers `incomplete_reason:
  "processes-remain"` with no seal. A control plane's relay into the namespace (`docker exec …
  socat`, asking for the status meanwhile) is not the daemon's descendant and is left alone. A
  path a filter's attribute names is read as
  its bytes on disk (in `worktree_tree` too: a review of a changed LFS file diffs its content,
  not a pointer); git's own line-end, `ident` and encoding conversions still apply to
  `worktree_tree`, and `raw_tree` holds the bytes. A restore of a capture without `raw_tree` is
  the one git that smudges. A tree path whose kind on disk is not the tree's (a regular file
  where `core.symlinks=false` kept a symlink's mode) makes a final flush `snapshot-failed`,
  never a capture that silently leaves its metadata out. A modification time is recorded exactly,
  as nanoseconds since the epoch (a JSON integer): outside signed 64 bits (before 1677 or after
  2262) it is a wide time, and every capture — an automatic one as much as a final one, in any
  class, a directory as much as a file — writes it exactly and a restore writes it back (before,
  it saturated to the last nanosecond of 2262, and a crash restore wrote that false time). A
  store keeps a wide time only if it reads the `wide_times` manifest feature: for one that does
  not, a final flush over a wide time is `unreadable`, naming the path. A restore of an older
  build refuses the number rather than write another time. A restore of a sealed capture never relinks
  a tracked hardlink group whose names hold different bytes (a workspace overlay can hold newer
  bytes for one of them than the tree): it fails naming the member instead of writing one
  name's bytes over the other's; any other restore leaves the two apart.
- **No user code over a store that cannot hold what a capture holds.** When `plan.get`'s
  `manifest_features` leaves out one this daemon writes (`git_trees`, `raw_names`, …), every
  capture over that store — the periodic ones a hard crash would be picked up from, not only the
  final one — restores less than the disk held. The boot is refused right after `plan.get`,
  before the head is materialized: no dotfiles, lifecycle step, harness, exec or session runs,
  and it exits **78** (`EX_CONFIG`, `EXIT_STORE_UNFIT`) with `refused: the store does not read
  the manifest feature(s) …; no user code is admitted over this store (nothing was
  materialized, nothing ran, nothing is saved)` on stderr (log field `outcome="store-unfit"`). A
  disk that already held work (a daemon restarting on its own staging) is left as it was: the
  platform keeps it as for any exit it does not know to be complete. A standby's `capture.replan`
  onto such a store is refused the same way, before it touches the disk: `policy-denied`, detail
  `{"reason":"store-unfit","unread":[…]}`. A recovery boot admits no writer and is not refused:
  it ships what the store can take, and its final flush answers `incomplete_reason:
  "store-fidelity"` and seals nothing, so it exits 75. The repository the writers get is part of
  the gate: a SHA-256 one needs the store to read `object_format`, a reftable one `ref_format`,
  whether the chain head's git section names the format or the repository is already on the
  disk (a restart, a standby's base). Before, both were left out of it: the boot admitted
  writers, and only their final flush said incomplete.
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
- **Complete means the registrar recorded the seal (decision 22).** A registered sealing capture
  is not enough: `capture.register` answers what it did with the seal the capture carries,

  ```json
  ← {"head_n":7,"head_capture_id":"…","seal":{"state":"recorded"}}
  ← {"head_n":7,"head_capture_id":"…","seal":{"state":"withheld","reason":"write-authority"}}
  ← {"head_n":7,"head_capture_id":"…","seal":{"state":"refused","reason":"executor"}}
  ```

  and a final flush answers `complete` only on `recorded` — the seal is recorded and stands, and
  the registrar attests the executor's completion on it. `withheld` (the registrar is still
  verifying what the seal names, or write authority over those objects is outstanding): the
  daemon sends the same register again — the registrar answers it as a lost ack, with where the
  seal stands now — up to six times, backing off (≈ 11 s), and still withheld the flush answers
  `incomplete_reason: "sealing"`; a final flush asked again asks again. `refused`, or an answer
  with no `seal` (a registrar from before this), is `sealing` too: fail closed. The registrar
  answers `seal` whenever the registered capture (`n`, `capture_id`) carries `final_seal`,
  including on the lost-ack path; it is absent otherwise.
- **Where an answer stands: order evidence by the executor, never by a clock (decision 17).**
  Every `capture.status` answer and every final `capture.flush` answer carries, beside `epoch`
  and `head_n`, `CaptureStatusReport` fields 27–30: `launch` (optional string: `plan.get`'s
  `executor`), `boot_id` (optional string: 32 hex, random per daemon process),
  `boot_generation` (optional uint64: the daemon processes that opened this disk's staging
  directory, this one included, persisted in `<staging>/boot-generation` and fsynced before the
  first answer; 0 when it could not be) and `observation` (optional uint64: strictly increasing
  within one boot, over every answer and every seal). Every final seal carries the same in the
  manifest: `final_seal.boot_id`, `.boot_generation`, `.observation` (optional, absent from an
  older daemon), its chain position being the manifest's `n`. An answer's content is computed
  under the number it takes, so a higher number never describes an older state; the answer to
  the final flush that sealed has a higher number than its seal. Ordering: same `(epoch, launch,
  boot_id)` — by `observation`; same `(epoch, launch)`, different boot ids, both generations
  above 0 and different — by `(boot_generation, observation)` (a recovery boot of the same disk
  counts up). Anything else — a field absent, a generation of 0, one generation under two boot
  ids, another epoch or launch — is incomparable. Core and Mend supersede evidence only by this,
  keep wall-clock times for display, and treat incomparable or contradictory evidence as unknown:
  no deletion, no "saved".
- **`complete` means current.** `capture.status` says `complete` only while the disk is as the
  last final flush captured it. After any later change the watcher reports it answers
  `incomplete_reason: "changed"` until a final flush is asked again. While a class polls (a
  directory it could not watch, a watcher overflow) nothing can vouch for it after the flush:
  the status reads `"unwatched"`, and a final flush asked again snaps that class and answers
  complete. A final flush's own answer is complete when its snaps, taken after every writer
  stopped, captured every class, a polled one included. It seals under the same predicate: before
  the sealing capture is staged the flush settles the watcher (a fence file through its event
  stream, so every change made before is counted) and checks that nothing changed since its
  first snap; when something did, it snaps every class again (three rounds at most), and a disk
  that keeps changing answers `incomplete_reason: "changed"` with no seal.
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
- **Keys the bucket already holds (decision 19).** `upload.urls` may answer a key in `present`
  (the registrar verified the stored bytes against the key and minted no URL): the executor
  takes it as uploaded, sends nothing, and goes on. Every PUT carries `If-None-Match: *`, and a
  412 is the same answer. A key the executor asked for that comes back in none of `urls`,
  `multipart` and `present` is an error (`no url for <key>`), never an upload taken as done.
- **`present` is negotiated (decision 20).** Every `plan.get` request says
  `"upload_answers":["present"]`. A registrar answers `present` only to an executor whose
  `plan.get` listed it, bound to that launch; to one that did not (an older daemon, including the
  binary on a retained disk a recovery boots) it mints a conditional URL as before, whose 412 the
  older daemon already takes as uploaded. An older daemon answered `present` failed with `no url`
  on every retry.
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
- **A write through another name of a file.** Watches follow directories, and a write through a
  hardlink's other name is an event on that name only. An event on any name of a multi-link file
  the snaps read dirties every class holding one of its names; a multi-link file with names in
  both classes, or names neither holds (linked into `/tmp`, a package store), is stat'ed on its
  class's maximum interval (10 s small, 120 s bulk), and one whose size, mtime or ctime moved
  dirties every class holding a name. Whatever that misses, a watched class is read whole on its
  reconcile interval (`Cadence::reconcile`, 60 s small, 600 s bulk) with no event at all; a snap
  that finds nothing changed stages nothing. A hard crash can lose at most that much of such a
  write, never an unbounded amount.
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
