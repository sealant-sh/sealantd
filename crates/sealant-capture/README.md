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
whose stat key (see "What a snap reads") and chunk list in the `DiskState` index (the engine's
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
the two trees compare identical (bytes, modes, mtimes, links — tracked files' too, through the
worktree metadata overlay), and the head over itself writes and changes nothing. This is what lets a standby executor pre-materialize the project base and apply the
claimed worktree's head over it (`capture.replan`).

## Worktree metadata and refs (`worktree_meta.rs`, `materialize.rs`, `gitpack.rs`)

A git tree carries a file's bytes and whether it is executable. A checkout writes every file
`0644`/`0755` under the umask with the time of the checkout, creates no directory git does not
track, and writes every name of a hardlinked file as a file of its own. Found by review
(2026-09-27): a tracked `0600` file came back `0644`, tracked hardlinks came back as two inodes,
and empty directories and every tracked mtime were lost.

- **The overlay.** Every small capture records the working tree's metadata beside its tree, in
  the workspace section's `worktree_meta` (see "`worktree_meta` in a manifest"): exact mode bits
  (`st_mode & 0o7777`) of files and directories, the root included; nanosecond mtimes of files,
  symlinks and directories; every directory no other class carries (empty ones among them); and
  hardlink groups among the worktree tree's files. It covers the paths the worktree tree names
  plus the directories of the working tree, minus `.git`, the daemon directory and staging, the
  harness home, bulk directories, nested repositories and every directory git ignores — those
  are the chunked classes', which carry their own metadata. The document is deterministic, so an
  unchanged tree is still an unchanged capture, and a change of mode or mtime alone is a capture.
- **Hardlinks across classes.** A tracked file whose inode has names outside the overlay — an
  ignored file (workspace class) or a file under a bulk directory — is matched against this
  snap's workspace listing and the bulk class's index (each bulk name checked on disk), and each
  such name is recorded in the document's `shared`. A restore links the name to the tracked file
  only when it holds exactly the tracked file's bytes: its class restored it from its own
  capture, which can be older (a bulk section captured before the shared inode was rewritten),
  and linking would then replace one content with the other. Left unlinked, each name holds
  exactly what its class captured, and the next bulk capture brings them together again. The
  relinked name's new inode goes into its class's index, so a head over itself writes nothing.
- **A path it cannot read is not gone.** A tracked path whose metadata cannot be read (a
  directory above it that cannot be searched; git carries its content from the previous capture,
  see "What a snap reads") keeps the previous document's entry in an automatic snap and counts as
  unreadable (`capture.status`'s `unreadable`, `tree/<path>`, once per directory git already
  reported); a final snap carries nothing and fails on it. The previous document is the daemon's
  in memory: after a restart such a path's entry is left out until it can be read again. A
  directory that cannot be listed keeps its own entry, mode `000` included, and a restore brings
  it back so.
- **Names that are not UTF-8** are kept byte for byte: a path is written as a *key*, the
  encoding dir objects use for names (bytes as UTF-8 when they are UTF-8 and hold no character of
  `U+10FF80..=U+10FFFF`; otherwise each such byte becomes `U+10FF00 + byte`, a bijection), and an
  escaped key also carries its bytes, hex, in `raw_path` (`raw_member` for a shared name).
- **Cost.** `examples/overlay_cost.rs` (release build, read-only) times the overlay of a small
  snap — `git ls-tree`, an lstat per path, the directory walk with its `git ls-files` of ignored
  directories, the encode and the chunking. On the Mend repository (1,349 tracked files, ≈ 22k
  directories under `node_modules`, which the walk never enters): 1,549 entries, p50 6.6–7.9 ms,
  p90 8.5–15 ms, a 157 KB document (17.5 KB compressed). On a synthetic repository of 100,000
  tracked files in 10,100 directories: 110,101 entries, p50 279–349 ms (a `git add -A` +
  `write-tree` of the same repository takes ≈ 140 ms), a 9.1 MB document in 13 chunks; one
  changed mtime uploads one new chunk, 49 KB compressed. Both are under the budget set for it
  (50 ms and 500 ms p50), so the overlay is read whole each snap; making it follow the watcher's
  dirty set is the next step if a repository needs it.
- **Applied last.** The materializer applies it after every class (restoring an ignored file or a
  bulk directory moves the mtime of the directory it lands in): it creates the directories the
  document names, removes the empty directories in its scope the document does not name, links
  hardlink groups, then sets modes and mtimes (files and symlinks, then directories deepest
  first), touching only what differs. `MaterializeReport::worktree_meta` counts what it changed;
  a head over itself changes nothing. The document is fetched and verified (each chunk and the
  whole document's sha256 and size) before anything is written, and a format this build does
  not read (`WORKTREE_META_FORMAT`) is refused then too.
- **Fails loudly.** A path the document names that is missing or of another kind after the
  checkout, or a `chmod`, `utimensat` or link that fails, fails the materialize; so does a
  directory of a chunked class whose mode or mtime cannot be set (it used to be ignored), a
  hardlink member whose canonical path is outside the class roots (it used to be skipped with a
  warning) and a failed link (it used to fall back to a copy; only a link across filesystems still
  does). Chunked-class symlinks get their own mtime back (`utimensat` without following them),
  on a delta too.
- **A capture without it** (every capture before this) restores as it always did.
- **Tracked files are the git class's.** A tracked file under a bulk-named directory (`build/`,
  `dist/`) is in both the worktree tree and the bulk section. A bulk section older than the
  worktree tree used to sweep a tracked file it never saw and write its older bytes back over one
  that changed since; the bulk class now neither writes nor sweeps a path the worktree tree names.
- **The ref set is the manifest's.** `packed-refs` is written from the manifest's refs, and every
  loose ref is removed, named by the manifest or not (only the ones it named went before), so a
  branch, tag, remote-tracking ref or stash the disk held beyond the manifest does not survive a
  materialize; `HEAD` is written as before.
- **Symbolic refs stay symbolic.** `refs/remotes/origin/HEAD` → `refs/remotes/origin/main` used
  to come back as a plain ref to the sha it resolved to. The git section now carries
  `symrefs` (name → target) beside `refs`; a restore writes each as a loose `ref: <target>` (a
  packed ref cannot be symbolic) after the loose refs are cleared, and leaves it out of
  `packed-refs`. A name or target that is not a plain `refs/…` name fails the materialize.

`tests/restore_metadata.rs` writes a worktree with all of it (modes, ns mtimes of files,
directories, symlinks and the root, empty directories, a hardlink pair, names that are not UTF-8,
loose and packed refs, a symbolic ref, an annotated tag, a stash), captures it, materializes it fresh and compares everything; drifts the
restored disk (extra loose and packed refs, `HEAD` moved, modes and mtimes off, a broken hardlink,
a stray empty directory) and materializes the head over it; changes metadata alone and checks it
is captured and restored by a delta and a fresh materialize; links a tracked file to an ignored
and a bulk name and checks all three come back as one inode, and apart but byte-exact when the
bulk section is older. `tests/delta.rs` compares the mtimes of the whole working tree.

Not covered: hardlinks between two names of other classes (an ignored file and a bulk file: each
class restores its own names), and a directory whose restored mode forbids the owner to write (a
later delta that writes into it fails, loudly).

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
  2. every writer is terminated and awaited: SFTP bridges are closed, a process group the
     fence stopped is continued, then `SIGTERM` (`SIGHUP` for sessions), then `SIGKILL` after
     the grace (`grace_ms`, else the shutdown grace; a hard shutdown kills at once) — the
     managed process groups and sessions, and at the same time every process outside them
     that `/proc` shows in the sweep's scope (`crates/sealantd/src/sweep.rs`), re-scanned
     until none is left: a writer that `setsid`'d or double-forked out of its group used to
     keep writing after the last snap. Scope: when sealantd is PID 1 of its PID namespace
     (`sealantd boot` as a container's entrypoint, Docker and Kubernetes), every process in
     the namespace, `docker exec`'d ones included; otherwise (a Lambda MicroVM, where Core's
     agent is PID 1 and starts `sealantd boot`; `sealantd serve`), every descendant of
     sealantd, which as the child subreaper inherits every orphan of what it started — the
     VM's agent and its `sealantctl` are never touched. sealantd, its threads, its own helpers
     (its own process group: the capture engine's `git`), kernel threads and zombies are left
     alone. A daemon that is not PID 1 of its namespace and did not become a child subreaper
     cannot see an orphan, so every final flush it runs is incomplete (`sweep-unavailable`,
     logged at boot). And every running container of the workspace's own Docker daemon is
     stopped (`POST /containers/{id}/stop?t=<grace>`, `crates/sealantd/src/docker.rs`) until
     the daemon reports none running: a container can bind-mount the worktree. The daemon is
     `SEALANT_WORKSPACE_DOCKER_HOST`, else a `DOCKER_HOST` Core reserves for the workspace's
     own daemon — `unix:///run/docker/docker.sock` (Docker in the MicroVM, the Kubernetes dind
     sidecar) or `tcp://docker:2375` (the Docker adapter's dind sidecar); any other
     `DOCKER_HOST` (a host daemon) is never touched. A container left running, or a daemon
     named and not reached, is `processes-remain`;
  3. the small class and, forced, the bulk class are snapped (`CadenceRunner::flush_final`),
     both as `final` snaps —
     whatever the bulk clocks say; a scheduled bulk build in progress yields to it at its next
     chunk boundary and the forced snap resumes its progress, re-reading only files whose stat
     key moved or whose last read was racy (see "What a snap reads"); a file or directory it
     cannot read fails the snap (`EngineError::unreadable()`), it never becomes a deletion;
  4. everything ships, bulk included (`Shipper::flush_final`).

  The daemon used to snap first and terminate after, so what an agent wrote during the upload,
  or from its `SIGTERM` handler, was on the disk only. The report's `complete` is true only when
  all four steps happened and nothing is pending on an unfenced lease; anything else is
  `complete: false` with a reason, never a success: a process that outlived `SIGKILL`
  (`processes-remain`), a failed snap of either class (`snapshot-failed` — a failed bulk snap
  used to be logged and ignored while older captures drained to zero; `unreadable` when it
  failed because it could not read work), a fence (`fenced` — a
  shipper already fenced used to answer "done"), a chain conflict (`conflict`), the caller's
  `deadline_ms` (`deadline`, or `ship-failed` when shipping kept failing until then). What
  could be staged still ships; what is left stays staged and is reported (`pending`,
  `pending_bulk`, `pending_bytes`, `refused`). Without a deadline — the daemon's own paths
  never give one — a transport failure is retried with backoff, a held capture is waited for, a
  lost lease is waited out, a refused register is uploaded again or rebuilt from disk, and only
  the process ending (or a fence, a conflict, a failed snap) stops it.

  A flush that returned at its `deadline_ms` ends nothing: the daemon stays up, admission stays
  closed, the writers stay stopped, the ship worker keeps uploading, and `capture.status` turns
  `complete` once it has (`incomplete_reason` stays `deadline` or `ship-failed` meanwhile). The
  harness a `capture.flush` terminated does not end the daemon either: boot waits for the stop
  (SIGTERM, SIGINT, `runtime.gracefulShutdown`) the control plane sends when it decides. One
  final flush runs at a time, and one asked again is idempotent: after a flush that stopped
  every writer it does not stop them again, a final snap over a final capture of an unchanged
  disk stages nothing, and it ships what is left. Only the daemon's own way out (SIGTERM,
  SIGINT, `runtime.gracefulShutdown`, the harness exiting on its own), whose final flush has no
  deadline, exits with 75 (`EX_TEMPFAIL`) when it ends incomplete — never 0 — after logging
  `FINAL CAPTURE INCOMPLETE` at error, and leaves the staging directory as it is.
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
- **A refused register is fixed, never dropped.** A registrar acknowledges only what it can
  restore: Mend's `capture.register` answers 422 `missing-objects` (a key the manifest names is
  not in the store, the keys in `missing`) or `unrestorable` (a section's tree would not
  restore) — review 2026-09-27 #4: retention removed a pack no live capture named while this
  executor's chunk index still pointed at it. The shipper used to retry that register every pass
  for good: the chain stopped and a final flush never completed. Now
  (`RegistrarError::RegisterRefused`, `Shipper::after_refusal`, `CaptureEngine::repair`):
  1. the first refusal of a capture whose named keys are all objects it staged (every object,
     when none is named) drops their upload acks; they are uploaded again (each checked against
     the store) and the capture registers again, in the same pass;
  2. a key it did not stage (a pack an earlier capture uploaded), a staged file already swept,
     or the same capture refused again writes a `RepairRequest` (`repair.json` in staging, so a
     restart finishes it) and nothing behind it ships. The engine, at its next snap (the
     cadence runner's small-class loop is woken for it; a final flush runs it straight away),
     forgets the named packs — chunk index, dir-pack map, acks; a missing git pack makes the
     next git pack a full one; none named, every pack of the rebuilt section — and snaps each
     class whose section named a missing key (the refused capture's class otherwise) as a
     capture at the refused one's `n`, with its parent. The captures staged after it are
     folded in: the rebuilt capture holds the disk as it is now and lists every object they
     staged, and a final one among them makes it final. A pack of the same chunks has the same
     key, so the rebuilt capture may name a key the store lost: it stages it this time.
  A final flush rebuilds and ships again until it registers (backing off from the second
  rebuild on), bounded only by its deadline. `capture.status` reports the refusal
  (`register_refused`, `register_refused_n`, `register_missing`, `register_refusals`,
  `repairing`, see "Wire additions"). A missing pack of another platform's bulk section
  (`other_bulk`) cannot be rebuilt here: it is logged and stays refused, reported.
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
`crates/sealantd/tests/final_sweep.rs` a `setsid`'d, double-forked writer stopped before the
last snap, its `SIGTERM` handler's file in the head; `crates/sealantd/src/capture.rs` also the
containers of a fake Docker daemon stopped (and a stuck one, or no daemon, incomplete), a
daemon without a subreaper incomplete, and a flush past its deadline completing in the
background and answering `complete` when asked again without a second quiesce;
`crates/sealantd/src/boot/capture.rs` another platform's dependency tree carried through an
executor's captures and restored on its own platform byte for byte.

## What a snap reads (`index.rs`, `roots.rs`, `watch.rs`)

A capture holds what is on disk, and says so when it cannot.

- **Nothing is excluded by name but git's own transients.** Outside the daemon's paths and the
  harness credential files, every regular file, directory and symlink under a class root is
  captured whatever it is called: an ignored `Cargo.lock`, `tmp/pids/server.pid`, a SQLite
  `-shm` (SQLite rebuilds a stale one when the first connection opens the database), a `.pack`
  without an `.idx`. Only inside a git directory (a `.git` component; the workspace class mounts
  the repository's git dir at `.git/`) are `*.lock`, `gc.pid`, `objects/**/tmp_*`,
  `objects/**/incoming-*` and a `.pack` without its `.idx` left out (`index::is_git_transient`):
  each is git's half-written state, made real by a rename the next snap sees, and a restored
  `index.lock` would make every git command in the workspace fail. Sockets, fifos and devices
  are not file content.
- **Local git-lfs objects are captured.** `.git/lfs/` rides in the workspace class (restored to
  `<root>/.git/lfs/`), so an object never pushed survives a replacement. The watcher does not
  descend into it (its sharded object directories would spend the watch budget); git-lfs writes a
  local object while `git add` writes the index, a watched change, and the snap it triggers walks
  `lfs/`, as does every forced snap.
- **Unreadable is not deleted.** The walk tells a path that vanished (`ENOENT`, `ENOTDIR`,
  `EISDIR`: removed, left out) from one that is there and cannot be listed, stat'ed or read
  (permission denied, an I/O error). A directory `git ls-files` could not open counts too (its
  ignored files are unknown). A `final` snap with anything unreadable fails with
  `index::UnreadableWork` naming every such path (`EngineError::unreadable`), so the flush is not
  complete, with `incomplete_reason` `unreadable` (not `snapshot-failed`) and the paths in its
  message; nothing is registered in place of the file, and staging stays. Any other snap carries each unreadable path's last read content from the index
  (content, size, mtime; the mode it has now), marks the entry `unread: true` (and a directory it
  could not list, which then holds what the last reads under it found), and logs a warning; a
  path never read before has nothing to carry and is left out of that automatic snap — counted in
  `unreadable` (not in `carried`) and named in `unreadable_paths`, so the control plane can show
  it — and the next snap that can read it captures it. The git
  class holds the same rule: `git add -A` skips a directory it cannot open with only a warning (an
  untracked one dropped out of the worktree tree; a tracked one fell back to the index's blobs,
  not the edit the last capture held), so the engine runs it with `LC_ALL=C`, reads the paths off
  its warnings, keeps those the filesystem confirms are unreadable
  (`gitpack::WorktreeTree::unreadable`), and an automatic snap gives each the previous capture's
  worktree-tree entry in the throwaway index (`GitRepo::worktree_tree_carrying`) while a `final`
  snap fails naming it (`tree/<path>`). A snap that fails after packing no longer makes its git
  tips the next pack's negatives (they once left the next capture's new objects out of every
  pack). Each snap's `SnapStats` counts `unreadable` paths, the `carried` ones and names the
  first 20 (`unreadable_paths`); `capture.status` reports the same for the last snap of each
  class (see "Unreadable paths on `capture.status`"). A SQLite
  `-wal` that vanishes mid-read no longer takes its database with it, and a hardlink group whose
  first member vanished is carried by the next one.
- **A file is read again unless its stat key says otherwise.** The key is size, mtime, ctime
  (nanoseconds), inode, device and mode. ctime cannot be set from user space, so a same-size
  overwrite that puts the mtime back is still seen (it used to be reported `unchanged`). A read
  whose file's ctime lies within `CaptureConfig::racy_window` (2 s, `index::RACY_WINDOW`) of the
  start of the read is racy: a write in the same timestamp tick would leave the stat unchanged,
  so the next build reads the file again (git's "racily clean" rule). And a path the watcher saw
  written or created since the last build of its class (`watch::Invalidations`, fed through
  `WatchSpec::invalidations`) is read again whatever its stat says. An index written before the
  key grew has no ctime and is read once more.
- **Names are bytes.** A name or symlink text that is not UTF-8 keeps its bytes (see "Dir
  entries: `raw_name`, `raw_target`, `unread`"); two names a lossy conversion would merge stay two
  files. `git ls-files -z` output is taken as bytes too.

`tests/read_fidelity.rs` holds each of these end to end (snap, ship, fresh materialize, compare
bytes); `index.rs`, `tree.rs` and `watch.rs` unit tests hold the pieces.

## Wire additions

### Unreadable paths on `capture.status`

`CaptureStatusReport` gains `optional uint64 unreadable = 17`, `optional uint64 carried = 18` and
`repeated string unreadable_paths = 19` (fields 15 and 16 are the final-flush report's
`complete` and `incomplete_reason`). `unreadable` is the number of paths the last snap of each
class could not read, summed over both (a directory counts once); `carried` how many of them had
their last captured content carried forward; `unreadable_paths` the first 20, virtual
(`tree/<path>` under the worktree, `.git/<path>`, `harness/<path>`), small class first. An older
daemon sends none of them. A client can show `2 paths unreadable · carried` and name them; after
a failed `final` snap they name what it could not read (`carried` 0).

### Dir entries: `raw_name`, `raw_target`, `unread`

Three optional dir-entry fields, written only when they apply, so every dir object that has none
of them encodes byte for byte as before (same digest, same section `format`; no bump). A reader
that predates them ignores them and keeps working, as Mend's `captures.ts` schema does (Effect
`Schema.Struct` ignores excess keys).

- `name` is a *key*: the name's bytes as UTF-8 when they are UTF-8 and hold no character in
  `U+10FF80..=U+10FFFF`; otherwise every byte of an invalid sequence, and every byte of such a
  character, becomes the character `U+10FF00 + byte` (all ≥ `0x80`). The mapping is a
  bijection (`tree::key_of` / `tree::bytes_of`). When the key was escaped, `raw_name` carries the
  name's bytes as lowercase hex, e.g. `{"name":"caf\u{10FFE9}","raw_name":"636166e9",…}` for
  `caf\xe9`.
- `raw_target`: the same for a symlink's `target` (its text, hex). A `hardlink-group` entry's
  `target` is a virtual path of keys and carries no `raw_target`: decode it with the rule above,
  or resolve it component by component through the entries' `name`s.
- `unread: true`: the entry could not be read at this snap and holds what the last read found
  (a file: its chunks, size, mtime), or is a directory that could not be listed. Only an
  automatic capture carries it; a `final` capture with unreadable work fails instead.

What Mend's reader (`packages/store/src/captures.ts`) needs: add
`raw_name: Schema.optionalKey(Schema.String)`, `raw_target: Schema.optionalKey(Schema.String)`
and `unread: Schema.optionalKey(Schema.Boolean)` to `DirEntry`; write a file, directory or
symlink at `Buffer.from(raw_name, "hex")` when present (refusing one that is empty, `.`, `..`,
or holds `/` or NUL, as sealantd does) and at `name` otherwise; create a symlink with
`Buffer.from(raw_target, "hex")` when present; decode a hardlink `target` by mapping each
character in `U+10FF80..=U+10FFFF` to the byte `codePoint - 0x10FF00` (Node's `fs` takes a
`Buffer` path); and surface `unread` (a capture holding one is partial for that path, like
`torn`). Until then such a name restores as its escaped key, as it restored lossily before.


### `manifest_format` on `plan.get`

The answer: the highest section format the registrar reads — walks to presign a plan, HEADs and
prices at register, keeps alive in retention. Absent = 1. At 2 the executor writes dir packs
(see "Dir packs"). Additive: an older executor ignores it, and a registrar that never answers
it gets format 1, as today.

The request: the highest section format the executor reads, `manifest_format: 2`
(`MAX_SECTION_FORMAT`; `PlanGetRequest::booting`, every plan a booting or re-planning daemon
asks for). Absent = 1: an executor from before dir packs. Mend answers `manifest_format` no
higher than it and refuses a plan holding a section above it (409 `manifest-format`, before the
claim) — an older reader takes a format-2 root digest for a key. The daemon reads a 409
`manifest-format` as that refusal (a protocol error, never a chain conflict).
`InMemoryRegistrar` does the same.

```json
→ {"worktree_id":"wt","epoch":0,"platform":"linux-x86_64-gnu","manifest_format":2}
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
`fenced`, `conflict`, `deadline`, `ship-failed`, `pending` (staged after the final flush),
`sweep-unavailable`, `unreadable` or `internal`; absent when `complete`. After a flush that
returned at its deadline (`deadline`, `ship-failed`), `complete` turns true once the worker has
shipped the rest: poll `capture.status`, or send the final flush again. An older daemon's report decodes with `complete: false`.

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

### `worktree_meta` in a manifest

`sections.workspace.worktree_meta`: the worktree metadata overlay (see "Worktree metadata and
refs"). Absent in every capture before it, and then not written, so such a manifest encodes byte
for byte as before.

```json
"workspace":{"root":"…","packs":["captures/wt/3/packs/<a>","captures/wt/3/packs/<b>"],"format":2,"dir_packs":[…],
             "worktree_meta":{"format":1,"size":5821,"sha256":"<sha256 of the document>",
                              "chunks":["<chunk sha256>",…],"packs":["captures/wt/3/packs/<b>"]}}
```

- `packs` holds the document's chunks and is a subset of the section's `packs`, so a registrar
  that presigns and retains the section's packs covers it with no change; `chunks` are CDC chunk
  ids, read from those packs as a file's chunks are (each verified against its id); the
  concatenation is `size` bytes whose sha256 is `sha256`.
- `format` is the document's (`1`). A reader refuses a format above the one it knows before it
  writes anything; an older executor ignores the field and restores as before.
- The document is compact JSON:

  ```json
  {"format":1,
   "entries":[{"path":"","kind":"dir","mode":488,"mtime":1599999000999999999},
              {"path":"caf\u{10ffe9}.txt","raw_path":"636166e92e747874","kind":"file","mode":384,"mtime":1600000000000000777},
              {"path":"empty","kind":"dir","mode":448,"mtime":1599827199999999986},
              {"path":"run.sh","kind":"file","mode":488,"mtime":1600000001123456796},
              {"path":"to-secret","kind":"symlink","mtime":1600000007123456838}],
   "hardlinks":[["link.txt","src/twin.txt"]],
   "shared":[{"path":"shared.txt","class":"bulk","member":"node_modules/pkg/shared.txt"},
             {"path":"shared.txt","class":"workspace","member":"tree/copy.log"}]}
  ```

  (`\u{10ffe9}` stands for that character, which JSON carries as UTF-8.) `entries` are sorted
  by `path` (worktree-relative, `/`-separated, `""` the root; no `.`, `..` or empty component).
  A path is a key: the bytes as UTF-8 when they are UTF-8 and hold no character of
  `U+10FF80..=U+10FFFF`, otherwise each byte of an invalid sequence (and of such a character)
  becomes `U+10FF00 + byte` — the encoding dir objects use for names — and an escaped key also
  carries its bytes, hex, in `raw_path`, which a reader takes over `path`. `kind` is `file`,
  `symlink` or `dir`; `mode` is `st_mode & 0o7777` (absent for a symlink); `mtime` is
  nanoseconds since the epoch. `hardlinks` (absent when empty) lists groups of two or more
  `file` keys sharing one inode, each sorted, the first being the one the others link to.
  `shared` (absent when empty) lists names another class carries of a tracked file's inode:
  `path` is the tracked file's key, `class` is `workspace` (then `member` is that class's
  virtual path, `tree/…`, `.git/…` or `harness/…`) or `bulk` (then `member` is root-relative),
  and `raw_member` carries an escaped member's bytes.
- Applying it (sealantd's `worktree_meta::apply`, after the worktree tree is checked out and every
  other class restored): create each `dir` that is missing; every other path must exist with its
  kind; remove the empty directories in scope that no entry names; link each group's members to
  its first path; link each `shared` member that holds exactly the tracked file's bytes to it
  (leave it otherwise); set files' and symlinks' mode and mtime (a symlink's own, never
  followed), then directories' deepest first. A reader that only lists or reads a class's files (Mend's
  `listCaptureDir`, `statCaptureEntry`, `readCaptureFile`, `materialize` of the workspace or bulk
  class) is unaffected: the overlay describes the git class's working tree, not a chunked class.

### `symrefs` in a manifest

`sections.git.symrefs`: symbolic refs other than `HEAD`, name → the ref it points at. Each is
also in `refs`, by the sha it resolved to at capture, so a reader that knows only `refs` reads
what it always did. Absent when empty, so a manifest without one encodes exactly as before.

```json
"git":{"packs":[…],"refs":{"refs/heads/main":"<sha>","refs/remotes/origin/HEAD":"<sha>",…},
       "head":"refs/heads/main","fsck":"verified",
       "symrefs":{"refs/remotes/origin/HEAD":"refs/remotes/origin/main"}}
```

### Register refusals on `capture.register` and `capture.status`

`capture.register` may answer 422 `{"reason":"missing-objects","message":…,"missing":[keys]}`
or `{"reason":"unrestorable","message":…}` (see "A refused register is fixed, never dropped"):
`RegistrarError::RegisterRefused`, never retried as it is. Any other 422 on it is a protocol
error. `CaptureStatusReport` gains:

```proto
optional string register_refused = 20;   // reason of the refusal being worked through
optional uint64 register_refused_n = 21; // that capture's chain position
repeated string register_missing = 22;   // the first 20 keys it named
optional uint64 register_refusals = 23;  // refusals seen since the daemon started
bool repairing = 24;                     // the refused capture waits to be rebuilt from disk
```

All absent / `false` from an older daemon, and when nothing is refused.

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

- §"Snap rules", Excluded always: `*.lock`, `gc.pid`, `objects/tmp_*` and `objects/incoming-*`
  are excluded only inside a git directory; SQLite `-shm` and pid files are captured; `.git/lfs`
  is captured (see "What a snap reads"). A path that cannot be read fails a `final` snap and is
  carried, marked `unread`, by any other. Change detection is by size, mtime, ctime, inode,
  device and mode, plus the racy window and the watcher's written paths.

- §"Capture format", Keys and Dir objects: dir objects travel in dir packs (the CDC pack
  container, `…/packs/<sha256>`) listed in a section's `dir_packs`, and name their children by
  digest, when the registrar announces `manifest_format` 2; `…/trees/<sha256>` objects remain
  format 1. Sections carry `format`.
- §"Write order": packs → dir packs → manifest → register.
- Byte-quota refusals (amendment of the capture channel): a refused capture is held and asked for
  again, never dropped.
- §"Manifest": sections gain `other_bulk`, the bulk sections captured on other platforms, keyed
  by platform and carried from capture to capture (see "`other_bulk` in a manifest").
- §"Manifest": the git section gains `symrefs`; the workspace section gains `worktree_meta`,
  the worktree metadata overlay, and
  §"Materialize" applies it after every class and reconciles the ref set to the manifest's
  (see "Worktree metadata and refs").
- §"Executor hooks": `capture.flush` takes `kind` (`suspend` | `final`), `deadline_ms` and
  `grace_ms`; the flush on `SIGTERM`/`SIGINT`/`runtime.gracefulShutdown`/harness exit is a
  final flush with no deadline, not bounded by the shutdown grace. A final flush closes
  admission and terminates the managed processes before it snaps, and reports `complete`; a
  daemon whose final flush is incomplete exits 75. A 409 `lease-lost` pauses shipping (never a
  conflict).
- §"Session channel": `plan.get` requests carry `manifest_format` (the highest section format
  the executor reads); `capture.register` may answer 422 `missing-objects` / `unrestorable`,
  which the executor fixes by uploading again or rebuilding the capture from disk in its place,
  never by dropping it.

- §"Capture format", CDC packs: "≤ 64 MiB, one PUT, never multipart" → packs stay ≤ 64 MiB but
  are uploaded as multipart at or above the shipper's threshold (default 16 MiB); git packs may
  exceed 64 MiB and are always multipart above it. The pack container is unchanged.
- §"Executor credentials": an executor also holds presigned per-part `UploadPart` URLs for its
  own keys, same scope and TTL as PUT URLs; Create and Complete stay with the registrar.
