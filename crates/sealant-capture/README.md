# sealant-capture

> Status (PR sealantd#71): the cadence is watcher-fed. The small class snaps 2 s after the last
> change and at most every 10 s while dirty; the bulk class has its own 30 s / 120 s clocks and
> yields to small snaps at chunk boundaries — when it builds, and when it uploads: a small capture
> is staged, shipped and registered ahead of a bulk capture still uploading (see "Small captures
> ahead of a bulk upload"); turn boundaries, checkpoints, `capture.flush` and the
> SIGTERM/SIGINT/`gracefulShutdown` paths force a small snap ahead of the timers (a `final`
> flush stops the executor's writers first and forces a bulk snap too; see "No work product is
> lost"). Watch budget not
> met, `IN_Q_OVERFLOW` or no backend → that class polls at its maximum interval (the stat walk).
> Still open: the registrar wire shape is provisional (`registrar.rs`).

The executor-side half of the session capture store (ADR-0015). A workspace is captured as two
classes of content-addressed objects in a bucket-shaped `BlobSink`: git objects as self-contained
git packs (`gitpack`), everything else as content-defined chunks in CDC packs (`chunk`, `pack`)
described by dir objects (`tree`), which travel in dir packs (see "Dir packs"). A `Manifest` ties one capture together; `ship` stages, uploads
and registers it through a `Registrar`; `materialize` rebuilds a workspace from a manifest.
`CaptureEngine` is the front door: `snap(class, kind)` stages a capture, `snap_preemptible` lets a
bulk build yield.

Nested repositories (a directory under the worktree holding a `.git`, with or without a commit
checked out, tracked as a gitlink or not) never enter the worktree tree: `GitRepo::worktree_tree`
enumerates them before its `git add -A` and names each in an `:(exclude)` pathspec, and the
chunked class carries their bytes (`tree/<path>/`). This does not depend on the git version: on
git 2.52 a commit-less nested repository is fatal to `git add -A` even with `--ignore-errors`,
and on any version an embedded repository with a commit would otherwise become a gitlink that
carries none of its bytes. The flag stays as belt and braces. A nested repository git already
ignores is carried by the ignored-files walk instead and is never named in a pathspec (naming an
ignored path makes `git add` exit 1).

## Materialize is a delta (`materialize.rs`, `roots.rs`)

`Materializer::materialize` brings the disk to a manifest rather than writing it out: a file
whose `(size, mtime, inode)` and chunk list in the `DiskState` index (the engine's
`workspace.json` / `bulk.json` under `.sealantd/capture/index/`, written by the materializer
for every file it lays down) match the plan entry is skipped, a symlink with the same text and
a hardlink member already on the canonical inode likewise; git packs already installed are not
fetched; the working tree moves from the tree last checked out to the plan's worktree
pseudo-ref through a two-tree `read-tree --reset -u` (a full `checkout-index` when nothing is
known about the disk). Files, symlinks and emptied directories the plan no longer names are
removed, and only inside what a capture would list (`ClassRoots`, the same policy the engine's
listings use): never the staging directory, excluded names, credentials, or the bulk
directories of a `"pending"` bulk section. Content and dir packs are fetched up front, eight GETs in flight (`PACK_GETS_IN_FLIGHT`), into
the pack cache (`.sealantd/capture/cache/`), and a pack already there is not fetched again.
`tests/delta.rs` measures it: a head applied over a
materialized base wrote 9 files / 213 KB where a fresh materialize writes 427 files / 1.7 MB,
the two trees compare identical (bytes, modes, mtimes, links), and the head over itself writes
nothing. This is what lets a standby executor pre-materialize the project base and apply the
claimed worktree's head over it (`capture.replan`).

## Sources beside the worktree

A capture-source workspace mounts nothing from the host, so content the control plane wants
beside the repository — Mend's organization folders and reference repositories — travels on the
plan. `plan.get` answers `sources`: per source a `name`, an absolute `path`, the object `key` of
a gzipped tar (its GET URL rides `get_urls`), the archive's `sha256`, its `bytes`, and
`read_only`. `crates/sealantd/src/boot/sources.rs` lays each one down at boot, before the control
socket binds.

- **Outside the worktree.** A path inside the working directory, or one the working directory
  sits under, fails the boot: content there would be listed by the next capture and shipped into
  the store as the session's own work. Paths must be absolute, under the workspace root, and free
  of `..`.
- **A copy, never a mount.** Nothing laid down here travels back — it sits outside every capture
  root. `read_only` additionally takes the writable bit off the tree, which is what a host bind
  mount would have done.
- **Stamped by content.** The archive's sha256 is the integrity check and the stamp
  (`<staging>/sources.json`), so a re-materialize re-extracts only what changed.
- **Re-planned with the worktree.** `capture.replan` lays down the sources of the worktree it is
  assigned: a standby executor boots under a placeholder, so the boot's plan named none of them.
- One source failing costs that directory, not the session: a fetch, digest or extraction failure
  is logged and skipped. Extraction runs in the staging scratch directory and is renamed into
  place, so a failure never leaves half a tree. An archive past 64 MiB is skipped; a byte budget
  belongs to the control plane that published it.

## Remotes of the worktree

The executor builds the worktree's repository itself: `git init`, then the head's packs. Remotes
are configuration of the control plane's own copy and never travel in a capture, so that
repository has none, and a harness that runs `git push origin` finds no `origin`. `plan.get`
answers `remotes`: per remote a `name` and a `url`. `crates/sealantd/src/boot/remotes.rs` sets
each one after the head is materialized, at boot and again at `capture.replan`, where a standby
learns which worktree it serves.

- **Name and URL only.** How a remote is authenticated stays the control plane's business; Mend
  points git's ssh at a transport that signs on its own machine.
- **Set, never pruned.** A missing remote is added and one that points elsewhere is updated. A
  remote the session added itself is left alone.
- A name or URL that could read as an option fails the boot: that is a control-plane bug. A git
  failure is logged and skipped, and the harness runs without that remote. URLs are never logged,
  since one may carry a credential.

## Re-plan (`capture.replan`)

A standby executor boots on the project base under a placeholder worktree id and epoch (Mend's
`standby-<id>`). When the control plane assigns it a worktree, `capture.replan` fetches
`plan.get` again (epoch 0, this build's platform, no worktree named: the token decides), takes
the worktree id and epoch the answer names, materializes the head as a delta over the disk with
the engine's own indexes (`CaptureEngine::materialize_delta`), and `CaptureEngine::rebase`s:
the key prefix moves, `Staging` moves its identity (ack markers live under
`uploaded/<worktree>/<epoch>/`, so nothing acked under the placeholder counts), queue entries
staged under the old identity are *foreign* — dropped by the rebase, and by the shipper if one
was in flight, whose fence then belongs to the old identity and is not this executor's —, chunk
locations under the old prefix are forgotten, a bulk build in progress is abandoned, the
repository closure is re-read as the negatives of the next pack, and the shipper's fence is
lifted. No snap runs meanwhile; the cadence resumes where it was. The daemon's heartbeat,
status and `lease.epoch` follow the new identity. A plan naming what the executor already has
is answered `unchanged`. `crates/sealantd/src/capture.rs` tests it end to end: base captured
for `wt-real`, standby boots as `standby-1`/epoch 7, the chain moves on, re-plan, the next
capture registers as `wt-real`/epoch 1 with the head as its parent.

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

## Small captures ahead of a bulk upload (`engine.rs`, `ship.rs`)

The chain is linear: every capture names the one before it as its parent, and the registrar
takes them in order. A bulk capture carries a dependency tree — on alpha (2026-09-27) a
`pnpm install` left ≈ 800 MB in ≈ 20k objects, which took the shipper twenty minutes — so every
small capture staged after it used to name it as its parent and wait for its whole upload. The
chain head stayed at the capture before the agent's edits, `capture.flush` timed out or answered
`pending 5`, and every checkpoint the control plane derived read `0 files · +0 −0`. Now:

- **The engine stages a small capture ahead of a queued bulk capture.** While the newest queued
  capture is a bulk one the shipper is not registering (`Staging::hoistable`), a small snap takes
  its place on the chain — its `n` and parent — with the bulk section of the manifest the bulk
  capture was staged on (another bulk section, or `"pending"`), and the bulk capture is staged
  again on top of it: the same objects, a new manifest whose git and workspace sections are the
  small capture's. The bulk capture is written at `n + 1` before the small capture overwrites
  its old slot, so it is never missing from the queue; its old manifest is swept. The two queue
  writes are one journaled step (see "A restage is one step"). A small `auto`
  snap coalesces with the small capture below the bulk one, never into the bulk one, and a bulk
  snap coalesces only with a bulk capture.
- **The shipper uploads a bulk capture's objects unclaimed and stops between objects** when the
  queue changes (a capture was staged ahead of it: it ships that one, then resumes where it
  stopped), when a flush is waiting, or at the caller's deadline. Its manifest registers once
  every object is up. One pass runs at a time (`Shipper::pass`).
- **A suspend `capture.flush` returns once every capture ahead of a bulk capture still
  uploading is registered** (`Shipper::flush_small`): the git pack, the worktree tree and the
  workspace class, which is what a change or a diff needs. The bulk capture keeps uploading in the worker and
  registers on top; `capture.status` reports it in `pending` and in `pending_bulk`, so a caller
  reads `pending == pending_bulk` as flushed for a change or a diff. A `final` flush does not
  return before the bulk capture is registered (see "No work product is lost").
- **Materialize is unchanged.** A head staged ahead of a bulk capture carries the older bulk
  section or `"pending"`; a materialize from a `"pending"` head neither restores nor sweeps the
  bulk directories.
- **Refusals.** A capture refused for the byte quota is held, never dropped (see "No work
  product is lost"); a small capture is staged ahead of a held bulk capture as ahead of any
  queued one.

`tests/small_ahead_of_bulk.rs` holds it against a sink that spends 250 ms per object on 164 bulk
objects, eight in flight (one object per directory, as for a registrar without dir packs): a
turn capture registers in ≈ 0.5 s and a flush returns in ≈ 0.5 s while the bulk upload runs, the
head materializes the edit without the dependency tree, and the bulk capture registers on top.
Before #98 the turn capture did not register within 5 s (40 ms per object, one at a time).

### PUT URLs: one pass, reused, and a 429 is transient

The same session ended its flushes on `no url for …/trees/<sha>`. A flush ran its ship pass
beside the worker's, over the same bulk capture (nothing kept two passes apart, and `claim` does
not refuse a claimed entry). Each pass took the PUT URLs the other had minted from the shared
cache, and the one that lost the race minted one key per `upload.urls` call: 161 calls for 164
objects in `tests/small_ahead_of_bulk.rs`. Against the registrar's call quota (600 an hour at
Mend) a 20k-object bulk upload runs out, and `RegistrarMinter` reported the 429 as
`no url for <key>: transport: upload.urls: http 429`, a `SinkError::NoUrl`, which the shipper
does not retry, so every pass failed until the quota's hour rolled over. Now one pass
runs at a time; a transport failure of a mint (5xx, 429) is `SinkError::Transport` and retried
with backoff, and a failed batch mint is retried as a batch instead of falling back to one call
per key; and `RegistrarMinter::prefetch_put` does not ask again for a key that holds a URL minted
within `PUT_URL_REUSE` (5 minutes), so a bulk upload that stopped mid-batch resumes on the URLs
it holds. A key the registrar answers without is still `NoUrl` ("the registrar answered
upload.urls without this key").

## Dir packs (`engine.rs`, `pack.rs`, `materialize.rs`)

Measured on alpha (2026-09-27, AWS Lambda MicroVM → S3 presigned PUTs): a pnpm `node_modules` of
≈ 800 MB was 20,878 objects — ≈ 13 CDC packs and ≈ 20,860 dir objects, one per directory, each
its own PUT at ≈ 70 ms. The upload took ≈ 24 minutes at 0.55 MB/s and ≈ 40–160 `upload.urls`
calls, and a restore would have been as many GETs, one at a time. A capture's dir objects now
travel in packs, so a capture is O(packs) objects and a restore O(packs) GETs.

- **Format.** A dir pack is the CDC pack container (`SLCP0001`): one zstd entry per dir object,
  the entry's `hash` being the dir object's sha256, keyed `captures/<wt>/<epoch>/packs/<sha256>`
  like any pack. In a format-2 section a dir entry's `child` and the section's `root` are dir
  object digests instead of keys, so a dir object's bytes do not depend on where it is stored,
  and the section lists its dir packs:

  ```json
  "bulk": {"root":"<sha256>","packs":["captures/wt/3/packs/<sha>",…],"platform":"linux-x86_64-gnu",
           "format":2,"dir_packs":["captures/wt/3/packs/<sha>",…]}
  ```

  A reader fetches the listed dir packs and resolves every digest through their trailing
  indexes (verifying each dir object against its digest), as it resolves chunks.
- **Versioning.** Each chunked section carries `format` (`manifest.rs`): absent = 1, one object
  per directory at `…/trees/<sha256>`, `root` and `child` being keys — every capture before this
  change, byte for byte (a format-1 section serializes exactly as before); 2 = dir packs. A
  materializer refuses a format above the one it reads before writing anything. Sections are
  versioned one by one because one manifest can hold both: a capture staged by this build over a
  head an older executor (or the control plane) wrote carries that head's bulk section as it is
  until the next bulk snap.
- **The registrar decides.** `plan.get` answers `manifest_format` (see "Wire additions"); the
  engine writes format 2 only when it is ≥ 2 (`DirFormat::for_registrar`, `CaptureConfig::dir_format`,
  set at boot and at `capture.replan`), and format 1 otherwise, so an executor never writes a
  capture its control plane cannot restore. Either format materializes here.
- **Dedup.** The engine keeps, per class and per epoch, where each dir object it packed is
  (`index/dirs.json`); a snap packs only the dir objects it has not packed before — for an edit,
  the path from the changed directory to the root — into one new dir pack, and lists the packs
  holding the rest. Per class, so a small capture staged ahead of a bulk one never names a pack
  only that bulk capture uploads.
- **Bound.** A section lists at most `MAX_DIR_PACKS` (16): past it the snap packs the whole tree
  into fresh packs, so a restore stays a couple of rounds of GETs however long the chain.

`tests/node_modules_measure.rs` (`--ignored`; public API only, so the same file ran on the
previous commit) captures a pnpm-shaped tree — 1000 packages, 6002 directories, 20,003 files,
three 6 MiB binaries — behind a sink that spends 40 ms on every request, then one edit deep in
the tree, then a fresh materialize of the head (release build; the materialize's wall time is
mostly writing 20k files, and varied between runs):

| step | before: requests | before: wall | after: requests | after: wall |
|---|---|---|---|---|
| first bulk capture, ship | 6018 (6005 PUT, 13 mint) | 241.5 s | 4 (3 PUT, 1 mint) | 0.12 s |
| one edit, ship | 11 | 0.44 s | 4 | 0.08 s |
| full materialize | 6016 GET | 241.9 s | 8 GET | 0.65–1.1 s |

The first bulk capture's 6003 dir objects are one 2.5 MB dir pack; the edit's 8 (the path to the
root) are one 53 KB pack; the restore fetches 6 packs and no dir object on its own.
`tests/dir_packs.rs` holds the counts, the bound, an old-format head and a mixed manifest.

## Uploads in flight (`ship.rs`)

Every object below the multipart threshold goes up eight at a time (`DEFAULT_UPLOADS_IN_FLIGHT`,
`CaptureConfig::uploads_in_flight`): a batch of up to 500 has its URLs minted in one
`upload.urls` call, then its PUTs share eight workers. Each worker asks the pass's stop condition
before it takes an object (a capture staged ahead, a waiting flush, the deadline), so a bulk
upload still yields between objects — at most eight in flight finish first. Each worker charges
its CPU to the pass's duty cycle and sleeps what the cycle owes, outside the lock. A byte-quota
refusal is reported over any other failure of the batch. Minted URLs are reused as before.

## No work product is lost (`ship.rs`, `cadence.rs`, `engine.rs`)

Dependency trees, build outputs and every other ignored file are work product: they come back on
restore, byte for byte, so the user never notices the compute changed.

- **A refusal holds, never drops.** A capture refused for the byte quota stays queued with its
  bytes, is reported in `capture.status`'s `refused`, and is asked for again after a backoff;
  the class keeps snapping (see "`sizes` on every `upload.urls`, and byte-quota refusals").
- **`"pending"` is not "nothing".** A head whose bulk section is `"pending"` restores the other
  classes and leaves the bulk directories on disk as they are — never swept — and the next bulk
  snap captures them.
- **A `final` flush stops the writers, then snaps, then finishes.** `capture.flush {kind:
  final}` and the SIGTERM / SIGINT / `runtime.gracefulShutdown` / harness-exit paths run
  `Runtime::final_flush` (`crates/sealantd/src/runtime.rs`), in this order:
  1. admission closes for good: no new process, exec (attached or not), session, SFTP bridge,
     execution, bind or re-plan is accepted, and the boot supervisor launches nothing more;
  2. every managed process and session is terminated and awaited: SFTP bridges are closed, a
     process group the fence stopped is continued, then `SIGTERM` (`SIGHUP` for sessions), then
     `SIGKILL` after the grace (`grace_ms`, else the shutdown grace; a hard shutdown kills at
     once);
  3. the small class and, forced, the bulk class are snapped (`CadenceRunner::flush_final`) —
     whatever the bulk clocks say; a scheduled bulk build in progress yields to it at its next
     chunk boundary and the forced snap resumes its progress, re-reading only files whose size,
     mtime or inode moved;
  4. everything ships, bulk included (`Shipper::flush_final`).

  The daemon used to snap first and terminate after, so what an agent wrote during the upload,
  or from its `SIGTERM` handler, was on the disk only. The report's `complete` is true only when
  all four steps happened and nothing is pending on an unfenced lease; anything else is
  `complete: false` with a reason, never a success: a process that outlived `SIGKILL`
  (`processes-remain`), a failed snap of either class (`snapshot-failed` — a failed bulk snap
  used to be logged and ignored while older captures drained to zero), a fence (`fenced` — a
  shipper already fenced used to answer "done"), a chain conflict (`conflict`), the caller's
  `deadline_ms` (`deadline`, or `ship-failed` when shipping kept failing until then). What
  could be staged still ships; what is left stays staged and is reported (`pending`,
  `pending_bulk`, `pending_bytes`, `refused`). Without a deadline — the daemon's own paths
  never give one — a transport failure is retried with backoff, a held capture is waited for, a
  lost lease is waited out, and only the process ending (or a fence, a conflict, a failed snap)
  stops it. One final flush runs at a time; a second waits, then runs again. A daemon whose
  final flush is not complete exits with 75 (`EX_TEMPFAIL`), never 0, logs `FINAL CAPTURE
  INCOMPLETE` at error, and leaves the staging directory as it is.
- **A deadline is the caller's.** The daemon used to clamp every flush's deadline to its
  shutdown grace (10 s, never configured at boot), so a caller that allowed 30 minutes for a
  dependency tree got 10 s. A flush now runs for exactly the `deadline_ms` it was given. A
  suspend flush sent without one (every client before this change) is bounded by the shutdown
  grace, as it always was; the grace is configurable (`SEALANT_SHUTDOWN_GRACE_MS` at boot,
  `sealantd serve --shutdown-grace-ms`) and bounds nothing else a capture does.
- **A lost lease pauses, it is not a conflict.** A 409 `lease-lost` from `upload.urls`,
  `upload.complete` or `capture.register` (the lease lapsed, was released before the executor
  was done, or a standby is not claimed yet) is `RegistrarError::LeaseLost`: the shipper pauses
  and asks again after 1 s, doubling to 30 s at most (`LEASE_LOST_BACKOFF`), with everything
  staged. It used to read as a wrong parent, a chain conflict, which ended a final flush with
  the captures still on the disk. A 409 naming another `live_epoch` is still a fence.
- **Another platform's dependency tree stays on the chain.** A head whose bulk section was
  captured on another platform is answered `"pending"` and not restored here, and it used to be
  dropped by this executor's next capture, so the platform that built it could never restore
  it. The engine now carries it in the manifest's `sections.other_bulk` (keyed by platform)
  through every capture; this executor's own bulk snap fills `bulk` beside it. A registrar
  answers an executor `bulk` when it was captured on its platform, else `other_bulk[platform]`,
  else `"pending"`. The executor itself never restores a bulk section stamped for another
  platform, whatever the registrar answered.
- **`pending_bytes` says what is at stake.** `capture.status` and every `capture.flush` report
  the bytes staged on this disk that no upload has taken yet, an object two captures share
  counted once (`Staging::pending_bytes`): what would be lost if the disk went now.
- **A restage is one step.** Staging a small capture ahead of a queued bulk capture writes two
  queue files (the bulk capture again at `n + 1`, the small capture in its old slot). A process
  that died between the two renames left a bulk capture naming a parent no entry held: it could
  never register, and nothing behind it either. `Staging::restage` now writes the whole change
  as a journal first (`restage.json`, synced, renamed into place: the commit point), then
  applies it; `Staging::open` and the engine's next snap finish a journal they find, and the
  shipper ships nothing while one is pending. A crash anywhere leaves the queue as it was or as
  the restage makes it. `tests/restage_crash.rs` kills it after each step and restarts.
- **A restart resumes its disk.** The engine records the capture it staged last
  (`index/last.json`). A boot whose staging names the plan's worktree and whose last capture is
  the head, or descends from it through the captures still queued (`CaptureEngine::pickup`),
  does not materialize the head — that would take back the queued captures and whatever changed
  after the last snap. The engine continues from the newest queued capture (a queued bulk capture
  can again have a small one staged ahead of it), the queue ships, and both classes are snapped
  once the cadence starts. When the lease moved to a new epoch while the daemon was down, the
  queued captures can never register and are dropped, but the disk holds everything they held:
  the tips they recorded are forgotten and the next snaps capture the disk afresh. A disk whose
  staging does not continue the chain (none, another worktree, a chain that moved on without it)
  is materialized over, as before.

`tests/no_loss.rs` and `tests/flush_modes.rs` hold each of these; `tests/quota_refusals.rs`
the refusals; `tests/restage_crash.rs` the restage; `crates/sealantd/src/capture.rs` a flush
that runs past the 10 s it was once clamped to, the grace bounding a suspend flush without a
deadline, a writer's `SIGTERM` handler landing in the head of a final flush and of
`runtime.gracefulShutdown`, and the fenced and cut-short final flushes answering incomplete;
`crates/sealantd/src/boot/capture.rs` another platform's dependency tree carried through an
executor's captures and restored on its own platform byte for byte.

## Wire additions

### `manifest_format` on `plan.get`

The highest section format the registrar reads — walks to presign a plan, HEADs and prices at
register, keeps alive in retention. Absent = 1. At 2 the executor writes dir packs (see "Dir
packs"). Additive: an older executor ignores it, and a registrar that never answers it gets
format 1, as today.

```json
← {"worktree_id":"wt","epoch":3,"head":{…},"get_urls":{…},"manifest_format":2}
```

### `pending_bulk` on `capture.status` / `capture.flush`

Of `pending`, the bulk captures whose objects are still uploading. Additive (`uint64` field 13 of
`CaptureStatusReport`; `0` from an older daemon). A control plane that treated `pending == 0` as
a complete flush reads `pending == pending_bulk` instead.

### `capture.flush`: `kind`, `deadline_ms` and `grace_ms`

The command carried `Empty`; it now carries `CaptureFlushArgs` at the same field (29), so an
older client's bytes decode as a suspend flush with no deadline.

```proto
enum CaptureFlushKind { CAPTURE_FLUSH_KIND_UNSPECIFIED = 0; CAPTURE_FLUSH_KIND_SUSPEND = 1;
                        CAPTURE_FLUSH_KIND_FINAL = 2; }
message CaptureFlushArgs { CaptureFlushKind kind = 1; optional uint64 deadline_ms = 2;
                           optional uint64 grace_ms = 3; }
```

`UNSPECIFIED` is `SUSPEND`. `grace_ms` (final only): how long managed processes get after
`SIGTERM` before `SIGKILL`, counted inside `deadline_ms`; absent, the shutdown grace. The result
is `CaptureStatusReport`, as before; a final flush answers it whatever happened, with
`complete` and `incomplete_reason` (below). `sealantctl capture flush [--final] [--deadline 15m]
[--grace 30s]` sends it (`500ms`, `90s`, `15m`, `2h`; a bare number is seconds).

| kind | first | snaps | returns when | no `deadline_ms` |
|---|---|---|---|---|
| `suspend` | — | small | every capture ahead of a bulk upload is registered | the shutdown grace |
| `final` | admission closed, writers terminated and awaited | small + bulk (forced), both must succeed | complete, or never can be (fence, conflict, failed snap), or the deadline | none |

### `complete` and `incomplete_reason` on `capture.status` / `capture.flush`

`bool` field 15 and `optional string` field 16 of `CaptureStatusReport`. `complete` is true only
after a final flush ran to the end on this executor — admission closed, every managed process
terminated and awaited, the small and the bulk class snapped after that, everything registered
— and while that still holds (nothing staged since, the lease not fenced). It is the only answer
a control plane may read as saved: `pending == 0` alone is not (a failed snap leaves nothing
pending). `incomplete_reason` says why not: `not-final`, `processes-remain`, `snapshot-failed`,
`fenced`, `conflict`, `deadline`, `ship-failed`, `pending` (staged after the final flush) or
`internal`; absent when `complete`. An older daemon's report decodes with `complete: false`.

```json
← {"pending":0,"pendingBulk":0,"pendingBytes":0,"complete":true}
← {"pending":3,"pendingBulk":1,"pendingBytes":2147,"fenced":true,"complete":false,
   "incompleteReason":"fenced"}
```

### `pending_bytes` on `capture.status` / `capture.flush`

`uint64` field 14 of `CaptureStatusReport`: bytes staged on the executor's disk that no upload
has taken yet, over every pending capture, each object counted once. `0` from an older daemon.
A caller that has to decide whether a workspace can go reads `pending == 0` (and
`pending_bytes` for how far off that is).

### `other_bulk` in a manifest

`sections.other_bulk`: bulk sections captured on other platforms, keyed by
`<os>-<arch>-<libc>`, each a bulk section as `bulk` is. Absent when empty, so every manifest
without one encodes exactly as before. A registrar reads its packs (and `dir_packs`) as it reads
`bulk`'s: it keeps them alive in retention, and answers `other_bulk[platform]` as the head's
bulk section to an executor of that platform, with its packs in `get_urls`.

```json
"sections":{"git":{…},"workspace":{…},
            "bulk":{"root":"…","packs":[…],"platform":"linux-x86_64-gnu","format":2,"dir_packs":[…]},
            "other_bulk":{"linux-aarch64-gnu":{"root":"…","packs":[…],"platform":"linux-aarch64-gnu"}}}
```

### `lease-lost` on the session channel

A 409 `{"reason":"lease-lost"}` from any call, without a `live_epoch` other than the caller's,
is a lost lease: the executor pauses shipping and asks again, and never reads it as a chain
conflict. Nothing new on the wire; the reading changed.

### `platform` on `plan.get`

The request carries the executor's `<os>-<arch>-<libc>` (the same key the bulk class stamps on
its captures, `engine::default_platform`). A registrar answers the head's bulk section as
`"pending"` when it was captured for another platform and `other_bulk` carries none for this
one (see "`other_bulk` in a manifest"), and omits its packs from `get_urls`:
the executor never restores a dependency tree built elsewhere, the control plane runs the
project's install in the workspace instead. A registrar that ignores the field, or a request
without it (an older executor), gets the head as is. `InMemoryRegistrar` implements the rule;
the materializer treats `"pending"` as nothing to restore and nothing to sweep.

```json
→ {"worktree_id":"wt","epoch":0,"platform":"linux-x86_64-gnu"}
← {"worktree_id":"wt","epoch":3,"head":{"n":7,"capture_id":"…","manifest_key":"…",
   "manifest":{…,"sections":{…,"bulk":"pending"}}},"get_urls":{…}}
```

### `sizes` on every `upload.urls`, and byte-quota refusals

`upload.urls` carries `sizes` for **every** key it asks for — the batch
(`RegistrarMinter::prefetch_put`), the multipart candidate, and the single-key fallback mint
(`put_url` on a cache miss, which declares that object's own length) — so the registrar can price
a whole batch before it mints anything, and a registrar that binds a signature to the exact
content length gets a URL the PUT can use. `UrlMinter::put_url` therefore takes the object's size,
and both PUT paths send that length as `Content-Length`.

The registrar prices a key once and refuses what would take the session past its byte budget:
413 on `upload.urls`, before a URL is minted, and 409 `byte-quota` on `capture.register` as the
backstop for a registrar that priced a key some other way. Both bodies carry the numbers.

```json
→ {"worktree_id":"wt","epoch":3,"keys":["captures/wt/3/trees/<sha>", …],
   "sizes":{"captures/wt/3/trees/<sha>":812, …}}
← 413 {"reason":"byte-quota","limit":8589934592,"used":8570000000,"requested":775000000}
← 409 {"reason":"byte-quota","limit":8589934592,"used":8570000000,"requested":775000000}
```

Executor side, both answers are `RegistrarError::QuotaRefused`, and the capture is held
(`Shipper::held`, `HeldCapture`): it keeps its place in the queue and every staged byte, the
class is named in `capture.status`'s `refused` (the capture is counted in `pending`), the
shipper logs the capture's `n`, class and the numbers at warn, and it asks again after a backoff
— 30 s, doubling per refusal in a row, 10 minutes at most (`HOLD_BACKOFF`) — one `upload.urls`
or `capture.register` call per ask, not one per ship tick. Nothing behind a held capture
registers first (the chain is ordered), but a small capture is staged ahead of a held bulk
capture, and a held class keeps snapping: a newer bulk capture replaces the held one in the queue.
Once the budget allows (retention retired packs, or the control plane raised it), the capture
registers and `refused` clears. Before #79 a 409 was classified as a wrong parent and a 413 as a
protocol error, and the ship worker re-ran the same call every 5 s for good (observed on the
cluster, 2026-09-14: a 775 MB bulk capture uploaded in full, then `ship pass failed
error=register n=4: … http 413` on every tick); from #79 until this change a refusal dropped the
capture and everything staged after it — a dependency tree, or an agent's edits, discarded for a
quota. `InMemoryRegistrar` takes a byte quota (`with_byte_quota`) so both refusal points are
tested (`tests/quota_refusals.rs`).

### Multipart uploads

Measured (R1, 2026-09): one presigned PUT from a Cloudflare sandbox to R2 runs at 37–47 MB/s,
four multipart parts in flight at 63.6 MB/s; AWS single-stream is ≈ 100 MB/s per flow. So the
shipper uploads objects at or above `MultipartConfig::threshold` (default 16 MiB; parts 16 MiB,
4 in flight) as S3-style multipart uploads, and the executor still never holds bucket
credentials: the registrar performs `CreateMultipartUpload` and `CompleteMultipartUpload`
server-side, the executor only PUTs parts to presigned part URLs and reports their ETags. Two
additions to the session channel, both additive (a registrar that ignores `sizes` and answers
`urls` alone gets single PUTs, as today):

`upload.urls` — request gains `sizes` (key → bytes) for the keys the executor would upload as
multipart; response gains `multipart` (key → upload) for the keys the registrar takes that way.
The object is cut into `part_size`-byte parts (the last shorter); part *i* (1-based) is PUT to
`part_urls[i-1]` with `Content-Length` and no conditional header; `urls` omits a multipart key.

```json
→ {"worktree_id":"wt","epoch":3,"keys":["captures/wt/3/packs/<sha>"],
   "sizes":{"captures/wt/3/packs/<sha>":150000000}}
← {"urls":{},
   "multipart":{"captures/wt/3/packs/<sha>":{"upload_id":"<store upload id>",
                "part_size":16777216,
                "part_urls":["https://…?partNumber=1&uploadId=…","https://…?partNumber=2&…"]}}}
```

`upload.complete` — new call. The registrar runs the store's complete with `If-None-Match: *`
(R2 enforces it on `CompleteMultipartUpload` and `CreateMultipartUpload`; S3 on complete) and
answers 409 `{"reason":"exists"}` when the key already holds an object; the executor treats that
as an identical object already present, keys being content-addressed. `size` in the response is
optional; when present the executor checks it against the file it uploaded.

```json
→ {"worktree_id":"wt","epoch":3,"key":"captures/wt/3/packs/<sha>","upload_id":"…",
   "parts":[{"part_number":1,"etag":"\"9b2c…\""},{"part_number":2,"etag":"\"…\""}]}
← 200 {"size":150000000}          |   409 {"reason":"exists","key":"captures/wt/3/packs/<sha>"}
```

Rules the registrar (Mend) implements: part URLs are minted only while the lease predicate
holds, like PUT URLs, and each counts against the URL quota; `part_size` is the registrar's
choice (≥ 5 MiB, equal for every part but the last — R2 requires it; ≤ 10,000 parts); ETags go
back to the store verbatim (quotes included); a key must be under the caller's epoch prefix;
`upload.complete` carries the usual 409s (`stale-epoch`, `lease-lost`) as well. An abandoned
upload (executor died, or the object was retried under a fresh `upload_id` after a part failed
past its retries) is expired by a bucket lifecycle rule for incomplete multipart uploads; there
is no `upload.abort` in v1.

Executor side: `BlobSink::put_multipart` (`sink.rs`) — per-part retry with backoff, parts in
flight from scoped threads whose CPU is charged to the shipper's duty cycle (network waits are
not), one complete with retry on transport loss, size check from the registrar's `size` or a
ranged GET where a GET URL exists. `LocalDir` writes the parts concatenated. `InMemoryRegistrar`
implements Create/Complete with a pluggable completer for tests (`tests/ship_multipart.rs`).

## Transport (`transport.rs`)

`ChannelTransport` is the one policy both outbound HTTP paths share (ADR-0015 §"Transport").
`HttpRegistrar::new` checks the endpoint against it and fails instead of constructing;
`PresignedHttp::with_transport` wraps the minter so every URL it answers is checked before a byte
is sent (`SinkError::NoUrl`, naming the host only). HTTPS with verified certificates; plain HTTP
to loopback, or anywhere under `SEALANT_CAPTURE_ALLOW_PLAINTEXT`; `SEALANT_CAPTURE_CA_PEM` /
`SEALANT_CAPTURE_CA_FILE` replace the channel's roots and `SEALANT_CAPTURE_OBJECT_CA_PEM` /
`_FILE` the object store's; redirects are never followed and proxy variables are not honoured.
`tests/channel_tls.rs` runs the channel against a real TLS listener with a throwaway PKI: the
named CA is accepted, an unknown issuer and a wrong name are refused with no request arriving,
and a 307 to a plain-HTTP host is reported, not followed.

A launcher that reaches the channel over plain HTTP on a private network (Docker and in-cluster
Mend installs today) must now say so, or boot refuses.

## Deviations from ADR-0015 pending amendment

- §"Capture format", Keys and Dir objects: dir objects travel in dir packs (the CDC pack
  container, `…/packs/<sha256>`) listed in a section's `dir_packs`, and name their children by
  digest, when the registrar announces `manifest_format` 2; `…/trees/<sha256>` objects remain
  format 1. Sections carry `format`.
- §"Write order": packs → dir packs → manifest → register.
- Byte-quota refusals (amendment of the capture channel): a refused capture is held and asked for
  again, never dropped.
- §"Manifest": sections gain `other_bulk`, the bulk sections captured on other platforms, keyed
  by platform and carried from capture to capture (see "`other_bulk` in a manifest").
- §"Executor hooks": `capture.flush` takes `kind` (`suspend` | `final`), `deadline_ms` and
  `grace_ms`; the flush on `SIGTERM`/`SIGINT`/`runtime.gracefulShutdown`/harness exit is a
  final flush with no deadline, not bounded by the shutdown grace. A final flush closes
  admission and terminates the managed processes before it snaps, and reports `complete`; a
  daemon whose final flush is incomplete exits 75. A 409 `lease-lost` pauses shipping (never a
  conflict).

- §"Capture format", CDC packs: "≤ 64 MiB, one PUT, never multipart" → packs stay ≤ 64 MiB but
  are uploaded as multipart at or above the shipper's threshold (default 16 MiB); git packs may
  exceed 64 MiB and are always multipart above it. The pack container is unchanged.
- §"Executor credentials": an executor also holds presigned per-part `UploadPart` URLs for its
  own keys, same scope and TTL as PUT URLs; Create and Complete stay with the registrar.
