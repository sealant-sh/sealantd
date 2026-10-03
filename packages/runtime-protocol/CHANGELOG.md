# @sealant/runtime-protocol

## 0.20.0

### Minor Changes

- c52f585: Upload URLs bound to their bytes. The executor lists `sha256` in `plan.get`'s `upload_answers`: it
  sends `x-amz-checksum-sha256` (the SHA-256 of the bytes, base64) on every PUT whose URL signs it,
  and declares in `upload.urls` the SHA-256 of each pack index, the one key whose name does not say
  it. A registrar on a store that cannot refuse an overwrite but checks a signed checksum (Garage) can
  then mint URLs that write those bytes or nothing: no write authority, and no seal waits for them to
  expire. An older registrar ignores both, and nothing changes for a URL that does not sign it.

### Patch Changes

- 9a7fa5b: A pack index's SHA-256 is declared on a multipart mint too, so a registrar that answers it as a
  single PUT can bind that URL to its bytes (before, it went unbound and the seal waited for it).
- 26ce30d: A final capture flush uses every core. On a 140,548-file, 2.3 GB dependency tree the snapshot
  took 28.9 s and now takes 2.9 s on a Ryzen 9950X3D. In a session on an i9-9900K, which has no SHA
  extensions, it took 69 s and now takes 9 to 10 s.

  - Small files are read, hashed and compressed on reader threads, in the order the build takes them.
  - A file too large to read ahead whole is still read in order, and its parts are hashed and
    compressed on those threads. 24 such files were 923 MB of that tree.
  - A pack's digest is computed on a thread of its own, and the pack is synced and named while the
    next one is written.
  - SHA-256 comes from `ring`, about twice as fast as before on a CPU without SHA extensions.
  - Objects of 16 MiB and more upload four at a time. They went up one at a time.
  - A single PUT may run for as long as its size needs at 512 KiB/s. It was cut at 10 minutes.

  The output is the same bytes: the same chunks, packs and tree as a build on one thread.

- 15c33aa: Capture leaves pi's and opencode's own login files out of the harness home, as it does Claude
  Code's and Codex's: `.pi/agent/auth.json` and `.local/share/opencode/auth.json`. A login made inside
  a session with either harness is never captured; their settings and sessions still are.

## 0.19.0

### Minor Changes

- 4ba2eeb: Dir packs, uploads in flight, and no work product lost (daemon-only; the packages ride the
  release train, and `capture.status`'s `refused` changes meaning).

  On alpha a pnpm `node_modules` of about 800 MB was 20,878 objects, about 20,860 of them dir
  objects, one per directory. The shipper uploaded them one PUT at a time, about 70 ms each, so the
  capture took 24 minutes, and a restore would have fetched them one GET at a time. When the
  registrar's `plan.get` answers `manifest_format: 2`, a capture's dir objects now travel in dir
  packs: the CDC pack container, keyed `…/packs/<sha256>`, listed in the section's new `dir_packs`,
  with `root` and every `child` naming a dir object by digest. Sections carry `format` (absent = 1,
  one object per directory, byte for byte what was written before). A registrar that does not
  announce format 2 gets format 1, and the executor reads both, including a manifest that holds one
  section of each. A later capture packs only the dir objects it changed, and a section lists at
  most 16 dir packs. Objects below the multipart threshold go up eight at a time, and a materialize
  fetches packs eight at a time. Measured with 6,002 directories and 20,003 files at 40 ms per
  request: the first bulk capture went from 6,018 requests in 242 s to 4 requests in 0.12 s, and a
  full restore went from 6,016 GETs in 242 s to 8 GETs in about a second.

  A capture refused for the byte quota is no longer dropped with everything staged after it. It is
  held in the queue with its staged bytes, its class is named in `capture.status`'s `refused`, and
  the executor asks again after a backoff (30 s, doubling, 10 minutes at most) until the budget
  allows. A held bulk class keeps snapping: the newer capture replaces the held one. A `final`
  flush (SIGTERM, SIGINT, `runtime.gracefulShutdown`) also snaps the bulk class. It ships
  everything with no deadline and returns only when the queue is empty or nothing can register (a
  fence or a chain conflict). A daemon that restarts on its own disk no longer materializes the head
  over captures it staged and did not ship, or over edits made after its last snap. The queue
  resumes, and both classes are snapped.

- 86db4e2: Five findings of the third Docker end to end.

  - A path longer than `PATH_MAX` no longer stops every capture. An untracked file 4,186 bytes
    below the root failed one `lstat`, which failed every snap for the rest of the session. Every
    filesystem call a snap or a restore makes takes a path of any length (resolved through
    `openat`, a run of components at a time); the paths git cannot reach (a file of 4,096 bytes or
    more, a directory it cannot open) are carried by the workspace class and restored from it, byte
    for byte. One path's metadata error, whatever it is, is that path's alone: an automatic snap
    counts it unreadable and carries its last capture, a final snap fails `unreadable` naming it.
    A directory the watcher cannot watch makes its class poll.
  - `capture.status` reports each class's failing snaps: `snaps` (field 26, `CaptureClassSnaps`:
    `class`, `snaps_failed`, `last_snap_error`, `snap_failing_since_unix_ms`). `complete` is false
    (`snapshot-failed`) while any class's last snap failed.
  - A final flush asked again after a complete one, with the writers stopped and the watcher having
    seen no change, snaps nothing: it answers in milliseconds and `complete` holds throughout (each
    one walked the dependency tree again for 2.5–3 s, `bulk_building` meanwhile).
  - `incomplete_reason` reads `in-progress` while a final flush runs (it read `not-final`).
  - Once `complete` is reported, nothing more is captured: the final flush seals the chain with a
    final capture when the newest one is of another kind (a scheduled bulk capture the final small
    snap was staged ahead of), and snaps the small class again after a bulk capture when tracked
    files have hardlinked names in the bulk class, so the final capture records the links.
  - A restore that cannot write names the path. `sealantd boot` runs as root (README); a daemon that
    is not root keeps its session journals under `$XDG_STATE_HOME/sealantd` or
    `~/.local/state/sealantd` when `SEALANT_SESSION_JOURNAL_DIR` is unset.

- eb954cf: The eighth end-to-end run's daemon findings (F1, F5).

  - **No pipe deadlock with a git the capture feeds (F1).** `git cat-file --batch-check` and `git
rev-list --stdin` got their whole input before their answer was read: once the answers filled
    the stdout pipe, git stopped reading and both sides waited for good. With 8 KiB pipes (root
    over `fs.pipe-user-pages-soft`) 1,349 cached raw-tree blobs were enough, and no capture was
    taken after the first for 17 minutes. Every git the capture feeds on stdin is now fed from a
    thread of its own while its stdout and stderr are read (`GatedChild::communicate`).
  - **A step past its bound is reported: `CaptureStatusReport.overdue` (field 31).** `step`,
    `started_unix_ms`, `running_ms`, `bound_ms`, while a snap (600 s) or a git it waits on (120 s)
    runs past its bound; absent otherwise and from an older daemon. An observation, not a
    failure. Mend reads it beside `incomplete_reason` and `snaps`: a running session whose capture
    has an `overdue` step is not idle.
  - **A git of the capture is killed at its limit** (`SEALANT_CAPTURE_GIT_LIMIT_SECS`, 900): the
    snap fails, `snaps` says so (`killed`), and it is taken again. The kill never signals a reused
    pid (it is taken before the child is reaped), a killed git's scratch index lock is removed by
    the next snap, and a git that writes the repository in place (a restore) is never killed.
  - **Tracked↔bulk hardlinks survive a recovery boot (F5).** A bulk name was looked up under the
    device number the dead daemon's index recorded, and a restarted container's overlay has
    another one: every link was dropped without being deferred, and the chain sealed without
    them. A bulk name is now matched by the inode it is on disk, and a final flush whose small
    snap depends on the bulk class snaps it again after the final bulk snap, staged or not (which
    also covers a lost bulk index).

- f5a8814: The eighth end-to-end run's remaining daemon findings (F7, F4b; F3 documented as unsupported).

  - **A standby no session claimed has nothing to save (F7).** A standby's boot (its launch is
    `standby:<id>` and its launcher named no worktree) writes `.sealantd/capture/unclaimed.json` on
    the disk's first boot, once its base is materialized. The first `capture.replan` that acts on
    its plan, or the first control command that admits a writer (`exec`, `writeStdin`,
    `openSession`, `attachSession`, `openForward`, `openSftp`, `bindMount`, `execution.start`),
    removes it durably before it acts. A final flush that still finds it answers at once, with no
    snap, no ship and no wait: `complete: true`, `pending: 0`, no `incomplete_reason`, under the
    placeholder's `worktree_id`, `epoch` and `launch`. It drops the placeholder's queue, the daemon
    ends by itself with exit **76** (`EXIT_NOTHING_TO_SAVE`), and nothing is admitted after that. A
    recovery boot on that disk exits 76 before `plan.get`, with `sealantd boot: nothing to save: a
standby no session claimed (…)` on stderr, which Core's recovery sweep already releases on
    (`nothing-to-save`). Once any claim or writer was admitted none of this applies again.

        Before, a claimed standby whose re-plan failed kept its placeholder captures queued forever
        (`lease-lost`). Its final flush never completed, and the launch waited 12 minutes, failed and
        needed a discard. Mend binds a `complete` answer to the lease epoch its claim took, so to act
        on the answer itself it must read a claimed standby's answer under the placeholder's epoch and
        its `standby:<id>` launch as nothing to save. Until then it sees the executor end.

  - **A base restores in its own formats (F4b).** When the plan's workspace class carries no
    `.git/config` or reftable tables (Mend's capture 0), the workspace sweep now leaves the ones
    `git init` wrote. After every class, the restore writes `core.repositoryformatversion`,
    `extensions.objectformat` and `extensions.refstorage` back if the repository no longer reads in
    the git section's formats. It does this before the boot adds remotes or seeds the engine.
    Before, a SHA-256 base restored as a SHA-1 repository and `git for-each-ref` failed on its
    64-hex `packed-refs`, and a reftable base lost every ref.
  - **Not supported (F3):** a repository that changes object format mid-session. Its next git
    section still lists the previous format's packs, and the registrar refuses the seal. Mend
    refuses SHA-256 and reftable projects at adoption.

- fadf797: A final `capture.flush` stops the executor's writers before its last snaps, and says whether it
  completed. Only `complete: true` means saved.

  The order is now: admission closes for good (no new process, exec, session, SFTP bridge,
  execution, bind or re-plan); every managed process and session is terminated (`SIGTERM`, then
  `SIGKILL` after the grace) and awaited; the small and the bulk class are snapped, and both must
  succeed; everything ships until nothing is pending. Before, the daemon snapped first and
  terminated after, so anything a process wrote during the upload or from its `SIGTERM` handler
  was lost. Writers outside the managed process groups are stopped the same way: every process
  in the PID namespace when sealantd is its PID 1 (a container), otherwise every descendant of
  sealantd, the child subreaper (a MicroVM), so a process that `setsid`'d or double-forked out of
  its group no longer writes past the last snap. Every running container of the workspace's own
  Docker daemon is stopped too (`SEALANT_WORKSPACE_DOCKER_HOST`, or the `DOCKER_HOST` Core sets for
  Docker in the MicroVM and the dind sidecars; a host daemon is never touched). The SIGTERM,
  SIGINT, `runtime.gracefulShutdown` and harness-exit paths use the same order.

  `CaptureFlushArgs` gains `graceMs` (field 3): how long managed processes get after `SIGTERM`
  before `SIGKILL`, counted inside `deadlineMs`. Absent, the daemon's shutdown grace.

  `CaptureStatusReport` gains `complete` (field 15) and `incompleteReason` (field 16). `complete`
  is true only after a final flush ran to the end: writers stopped, both classes snapped, nothing
  pending, and the lease not fenced. Otherwise `incompleteReason` is one of `not-final`,
  `processes-remain`, `sweep-unavailable`, `snapshot-failed`, `unreadable`, `fenced`, `conflict`,
  `deadline`, `ship-failed`, `pending` or `internal`. A final flush that returned at its deadline
  ends nothing: admission stays closed, the writers stay stopped, the upload goes on, and
  `complete` turns true once it is done; asked again, the flush neither stops the writers again nor
  takes a new capture of an unchanged disk. A final flush now answers with the report whatever happened, and never as a
  success while work is left: a failed bulk snap used to be logged and ignored, and a flush on an
  already fenced lease used to answer as finished with captures still staged. A report from an
  older daemon decodes with `complete: false`, so `pending == 0` alone must not be read as saved.

  When the daemon's own way out (SIGTERM, SIGINT, `runtime.gracefulShutdown`, the harness exiting)
  ends with its final flush incomplete, it exits with 75 (`EX_TEMPFAIL`) and keeps its staging
  directory, instead of exiting 0. A daemon that is not a child subreaper (and not PID 1 of its
  PID namespace) answers every final flush `sweep-unavailable`.

  A small capture staged ahead of a queued bulk capture now rewrites the queue as one journaled
  step (`restage.json`), finished on the next open or snap. A crash between the two queue writes
  used to leave the bulk capture naming a parent no entry held, which blocked shipping for good.

  `sealantctl capture flush --final --grace 30s` sends the grace.

- c1d2f9b: `capture.flush` takes a kind and a deadline, the daemon no longer cuts a flush at 10 s,
  `capture.status` reports `pending_bytes`, a lost lease pauses shipping instead of ending it, and
  another platform's dependency tree stays on the chain.

  `capture.flush` now carries `CaptureFlushArgs { kind, deadline_ms }` at the same field
  (`captureFlush`, 29). `kind` is `CaptureFlushKind.SUSPEND` or `CaptureFlushKind.FINAL`, and
  `UNSPECIFIED` reads as `SUSPEND`, so an older client that sends an empty message gets what it
  got before. A suspend flush is unchanged: it returns once every capture ahead of a bulk upload is
  registered. A final flush snaps the small class and forces a bulk snap, which a scheduled bulk
  build in progress yields to. It then ships until nothing is pending, bulk included, or until a
  fence, a chain conflict, or the caller's `deadlineMs`. With no deadline only the process ending
  stops it. The daemon's own SIGTERM, SIGINT, `runtime.gracefulShutdown` and harness-exit flushes
  are final flushes with no deadline. `sealantctl capture flush [--final] [--deadline 15m]` sends
  the command.

  The daemon used to clamp every flush's deadline to its shutdown grace, 10 s and never set at
  boot. A flush now gets exactly the deadline it was sent. A suspend flush sent without one is
  still bounded by the grace, which `SEALANT_SHUTDOWN_GRACE_MS` (boot) and
  `sealantd serve --shutdown-grace-ms` now set.

  `CaptureStatusReport` gains `pendingBytes` (field 14): the bytes staged on the executor's disk
  that no upload has taken yet, each object counted once. It is `0` from an older daemon.

  A 409 `lease-lost` from the session channel was read as a wrong parent, a chain conflict, and a
  final flush stopped on it with the captures still staged. It is now a lost lease: the shipper
  pauses, asks again after 1 s (doubling, 30 s at most), and keeps everything staged. A 409 that
  names another `live_epoch` is still a fence.

  An executor that continued a head whose bulk section was built on another platform (answered
  `"pending"` by `plan.get`) dropped that section at its next capture, so the platform that built
  it could never restore it. Manifests now carry such sections in `sections.other_bulk`, keyed by
  platform, through every capture. The executor's own bulk snap fills `bulk` beside them, and a
  registrar answers `other_bulk[platform]` to an executor of that platform. The field is absent
  when empty, so existing manifests encode byte for byte as before.

- 529e94d: A register the control plane refuses is fixed, never dropped; a final flush names unreadable work;
  `plan.get` says which manifest format the daemon reads.

  `capture.register` may answer 422 `missing-objects` (an object the manifest names is not in the
  store, the keys in `missing`) or `unrestorable` (a section's tree would not restore). The daemon
  used to retry the same register forever, so the chain stopped and a final flush never completed.
  It now uploads the objects it staged again and registers again; when a named key is one it did
  not stage (a pack retention removed while the daemon's chunk index still pointed at it) or the
  same capture is refused again, it rebuilds that capture from disk in its place — same position,
  same parent, the named packs forgotten and read again — and folds the captures staged after it
  into it. `capture.status` gains `register_refused`, `register_refused_n`, `register_missing`,
  `register_refusals` and `repairing` (fields 20–24 of `CaptureStatusReport`).

  A final flush that fails because it cannot read work reports `incomplete_reason` `unreadable`
  (it said `snapshot-failed`). Every `plan.get` sends `manifest_format: 2`, the highest section
  format the daemon reads, so a control plane can refuse it a head it could not restore and cap the
  format it is told to write; a 409 `manifest-format` answer is read as that refusal. The worktree
  metadata overlay names paths with the same key encoding as dir objects (one implementation, the
  same bytes).

- 8ad0498: A capture holds what is on disk, and a final one fails when it cannot (daemon-only; the packages
  ride the release train).

  A user's `*.lock`, `*.pid`, SQLite `-shm` and `.pack` files are captured; only git's own
  transient files inside a git directory are left out. Local git-lfs objects (`.git/lfs/`) are
  captured. A file or directory that exists but cannot be read is no longer captured as deleted: a
  `final` capture fails naming it, and any other capture carries its last read content, marked
  `unread`. A same-size overwrite that puts the mtime back is seen (the change key includes the
  ctime), a read right after a change is not trusted by the next capture, and a path the watcher saw
  written is read again. File names and symlink text that are not UTF-8 keep their bytes: dir
  entries gain optional `raw_name`, `raw_target` and `unread` fields, written only when they apply,
  so every existing dir object is unchanged.

  A directory `git add -A` cannot open no longer drops out of the worktree tree (or falls back to
  the index's blobs): an automatic capture carries the previous capture's entries for it, and a
  final capture fails naming it. `capture.status` gains `unreadable`, `carried` and
  `unreadable_paths` (fields 17–19 of `CaptureStatusReport`): what the last capture of each class
  could not read, never taken as deleted.

- a12dcee: A restore brings back the working tree's metadata and exactly the captured refs
  (daemon-only, plus one additive manifest field).

  A git tree carries a file's bytes and its executable bit, nothing else, so a restored session
  got every tracked file `0644`/`0755` with the time of the restore, lost its empty directories,
  and got two files where it had one hardlinked file. A capture's workspace section now carries
  `worktree_meta`: exact modes, nanosecond mtimes of files, symlinks and directories (the root
  included), the directories git does not track, and hardlink groups, as a JSON document chunked
  into the section's own packs (its `packs` are a subset of the section's, so retention and
  presigning need no change). The materializer applies it after every class and fails, instead
  of reporting a partial restore, when a path cannot be brought to it. A manifest without the field
  restores as before, and a manifest with it encodes the field only when present. The shape is in
  `crates/sealant-capture/README.md`, "`worktree_meta` in a manifest".

  Names that are not UTF-8 are kept byte for byte in the document, written as the same escaped keys
  dir objects use for names with the bytes in hex beside them. A tracked file hardlinked to an
  ignored file or to a file under a bulk directory comes back as one inode when every name holds
  the same bytes, and as separate byte-exact files when the bulk capture is older.

  A rematerialize removed only the loose refs the manifest named, so a branch, a remote-tracking
  ref or a stash the disk held beyond the manifest survived it. Every loose ref is now removed and
  `packed-refs` holds exactly the manifest's refs. Symbolic refs other than `HEAD`
  (`refs/remotes/origin/HEAD`) came back as plain refs; the git section now carries them in an
  additive `symrefs` map (name → target, absent when empty) and a restore writes them symbolic.

  Chunked-class symlinks get their own mtime back, and a directory mode or mtime, a hardlink or a
  hardlink canonical outside the class roots that cannot be restored fails the materialize instead
  of being skipped. A bulk section older than the worktree tree no longer sweeps or overwrites a
  tracked file under a bulk-named directory such as `build/` or `dist/`.

  A tracked path whose metadata cannot be read (under a directory that cannot be searched) keeps
  its previous entry in an automatic capture and is counted in `capture.status`'s `unreadable`; a
  final capture fails on it, as it does on any work it cannot read.

  A restored `packed-refs` claimed git's `peeled fully-peeled` traits without carrying a single
  `^<peeled>` line, which tells git no ref in it is an annotated tag: on git 2.43 and 2.52
  `git describe` found no annotated tag, `show-ref -d` and a fetch from the restored repository
  lost `v1^{}`, and 2.52's `for-each-ref %(*objectname)` failed with "bad tag". The file now
  claims only `sorted`, and git peels each tag from its object.

- 529e94d: A resumed executor keys its bulk captures by the workspace's libc, captures incrementally, and
  reports a bulk build in progress.

  - The bulk platform key (`<os>-<arch>-<libc>`, on `plan.get` and on every bulk section) now names
    the workspace userland's C library, detected at run time (the musl loader, else
    `ldd --version`), the way Mend's probe does. The release daemon is a static musl binary and
    said `linux-x86_64-musl` in glibc workspaces, so every resume treated the head's dependency
    tree as another platform's and installed it again. A section an older daemon stamped `-musl`
    there costs one more install: it is kept in `other_bulk`, never dropped, and the next bulk
    capture fills `bulk` under `-gnu`.
  - A restored executor learns where the head's chunks are (the packs the registered head names,
    from the materializer's pack cache), so its next capture reads and uploads only what changed;
    it used to read and upload the whole dependency tree again after every resume.
  - `capture.status` gains `bulk_building` (field 25 of `CaptureStatusReport`), and
    `pending_bytes` counts what a bulk build in progress has staged: a drain read "nothing
    pending" while hundreds of megabytes were staged by a build not yet queued.

- 4a26ae2: The tenth adversarial review's daemon findings (#1, #2), the carried ninth-review #3, and the
  format admission gap; cross-repo decision 29.

  - **Every object a reflog names is packed (#1).** `git rev-list --reflog` lists commits only: a
    blob, a tree or an annotated tag a ref was moved away from was left out of a sealed capture in
    either ref backend, and the restored reflog named objects the repository did not hold. The
    other objects are now listed with `--objects`, the commits negated so no commit's tree is
    walked.
  - **Nested repositories that share git storage (#2, decision 29).** A linked worktree inside the
    workspace keeps its `.git/worktrees/<name>` administrative directory (index, `HEAD`,
    `ORIG_HEAD`, reflog, per-worktree refs) in the workspace class, and its `HEAD`, refs, reflogs,
    every index stage and operation state join the top-level closure. A nested repository whose
    alternates (or common directory) are the top-level object store gets the objects its own state
    reaches there in a further pack of the git section. One whose git directory, common directory
    or alternates are outside the workspace makes a final flush `snapshot-failed`, naming it; so
    does one under a bulk directory that borrows the top-level store.
  - **Times outside 1677–2262 are exact (review 9 #3, carried).** A modification time is recorded
    as nanoseconds since the epoch, exactly: a dir entry's and a worktree metadata entry's `mtime`
    is a JSON integer outside signed 64 bits for such a time (a wide time), written by automatic
    captures as by final ones, and restored exactly. Before, an automatic capture saturated it and
    a crash restore wrote the last nanosecond of 2262. A new manifest feature, `wide_times`: a
    store that does not read it gets no complete final flush over a wide time (`unreadable`); a
    registrar reports it held when a dir entry of the answered sections, or a worktree metadata
    entry, has an `mtime` outside signed 64 bits.
  - **The repository is part of writer admission.** A SHA-256 repository needs the store to read
    `object_format` and a reftable one `ref_format`, whether the chain head names the format or the
    repository is on the disk: the boot exits 78 (`store-unfit`) and a standby's re-plan is
    refused before anything is materialized, instead of admitting writers whose final flush then
    says incomplete.

- 9f88b20: The eleventh adversarial review's daemon findings (#1, #2) and the carried tenth-review #6;
  cross-repo decisions 29, 33 and 35.

  - **Bare repositories and symlinked object stores are part of the closure (#1, decision 29).**
    A git directory with no worktree — a bare repository in the worktree tree, an ignored or bulk
    directory, or `.git/modules/` — is found by its `HEAD` (as git decides a git directory) and
    classified like a nested repository. Every nested repository's primary object store is
    resolved through symlinks before its alternates are followed, and relative alternates are
    taken from the store's real path. One that borrows the top-level store, through alternates or
    an `objects` symlink, gets the objects its own state reaches there packed beside the closure;
    one whose storage is outside the workspace, or one that borrows it where git cannot be asked
    what its state reaches, makes a final flush `snapshot-failed`, naming it. Before, a bare `child.git` borrowing the top-level store
    and a nested `.git/objects -> ../../.git/objects` both sealed without the objects only they
    reached.
  - **Only git's own transaction files are transient (#2, decision 33).** The name filter inside a
    git directory is an allow-list of git's lockfiles and temporary objects, each where git writes
    it (`index.lock`, root refs' locks, `config.lock`, `packed-refs.lock`, `refs/**.lock`,
    `logs/**.lock`, the object store's locks and `tmp_*`/`incoming-*`, the same in
    `worktrees/<name>/` and `modules/<name>/`). Any other file is captured in every class: a hook
    project's `.git/hooks/Cargo.lock` and a config include called `.git/personal.lock` were
    dropped, and a sealed restore lost them. A `.pack` is judged by its `.idx` only in
    `objects/pack/`. A transaction lock found by a final flush is stale (every writer was stopped)
    and is dropped, never restored and never a reason to refuse the flush.
  - **A final flush names itself on the wire (carried review 10 #6, decision 35).** From the moment
    a final flush begins — a drain, a runtime deadline, `SIGTERM`, a recovery boot — every
    `upload.urls` and `capture.register` the executor sends carries `"flush":"final"` until it
    exits, so the registrar can exempt preservation from its byte and call quotas. Additive: an
    older registrar ignores the member and meters the request as before.

- fe8b168: The second adversarial review's daemon findings, and three cross-repo contracts.

  - **A completed final flush is sealed on the chain.** When a final flush completes (every writer
    stopped, both classes snapped after that, everything staged registered), sealantd registers
    one more capture — the newest one's sections, `kind: final`, `n` = head + 1 — carrying
    `final_seal: {complete: true, epoch, executor}`, and reports `complete` only once that
    register is acknowledged. `executor` is `plan.get`'s new `executor` answer (the executor the
    session token was issued for), else `SEALANT_WORKSPACE_ID`. A capture staged later carries no
    seal; the next final flush seals again. A flush that returned at its deadline reads
    `incomplete_reason: "sealing"` once everything else registered, until the final flush is asked
    again (new reason code).
  - **`plan.get` lists the manifest features the daemon reads**:
    `manifest_features: ["worktree_meta","symrefs","other_bulk","raw_names","final_seal"]`. A 409
    `manifest-features` is a protocol error naming the missing features.
  - **Recovery boot.** `SEALANT_RECOVERY=1`, or the marker file `/.sealantd-recovery` (Core
    `docker cp`s it into a kept container before `docker start`), boots a retained executor that
    resumes its own staging and never materializes over its disk, runs no lifecycle step, dotfiles
    or harness, admits nothing, and runs the final flush when asked or on its stop (exit 0 only
    when complete, else 75; a recovery boot that cannot start exits 75).
  - **No control peer is spared by the final sweep.** The relay carrying a final flush
    (`docker exec … socat`) is swept like any other process; the outcome survives it
    (`capture.status`, or the final flush asked again, answers it without a second quiesce). Only
    helpers sealantd spawned itself (the spawn gate's pids, in its process group, and their
    children there) are left running; joining sealantd's process group spares nothing.
  - **Git refs are kept as bytes.** Two branch names that differ only in bytes that are not UTF-8
    no longer collapse into one (one branch's unique commit was lost); ref names, symbolic targets
    and a symbolic `HEAD` are `key_of` keys in the manifest, restored byte for byte. A dangling
    symbolic ref (`refs/remotes/origin/HEAD` → a missing branch) is kept and restored.
  - **A hardlink between an ignored file and the bulk class restores as one inode.** The worktree
    metadata document gains `cross_links` (additive; format stays 1): inode groups no tracked file
    names, spanning the workspace and bulk classes, linked again after both classes restore.

- 7b4ccdd: The third adversarial review's daemon findings, and the executor side of cross-repo decisions
  5–8.

  - **Capture starts before user code (decision 8).** The capture engine starts right after the
    head is materialized, before dotfiles, lifecycle setup/startup steps and the harness (setup
    could write for hours with no capture running). Every exit after that point runs the final
    flush and exits 75 when it is incomplete: a failed dotfiles apply, WSS frontend, lifecycle step
    or harness launch included.
  - **`complete` means current (decision 7).** `capture.status` and the final flush's answer (the
    same report) say `complete` only while the disk is as the last final flush captured it. Any
    later change signal or a watcher overflow reads `incomplete_reason: "changed"` (new reason
    code) until a final flush is asked again.
  - **The seal names the launch (decision 5).** `final_seal.executor` is `plan.get`'s `executor`
    and nothing else. `SEALANT_WORKSPACE_ID` is no longer read for it, and a plan with no
    `executor` gets no seal. A re-plan takes the new plan's executor.
  - **Refused keys are never written again (decision 6).** Object keys gain a key generation,
    `captures/<worktree>/<epoch>/g<n>/{packs,trees,manifests}/<sha256>`, kept per worktree and
    epoch in staging. Every register refusal rebuilds the capture from disk under the next
    generation, so the same bytes go up under a new key. The shipper no longer puts the refused
    keys again, and a rebuild carries none of them. Keys without the segment still read.
  - **`git_trees` manifest feature.** Written only for a registrar whose `plan.get` lists it. The git
    section names `worktree_tree`, `index_tree` and `raw_tree` in their own fields, and `refs` holds
    the repository's refs whatever their names (a user ref under `refs/sealant/capture/` was
    dropped by every restore). `raw_tree` holds each file's bytes as they are on disk, and a
    restore writes them back without smudge, end-of-line or encoding conversion: CRLF under
    `text eol=lf`, clean filters, `working-tree-encoding`, `eol=crlf` and `ident` come back byte
    for byte. The user's index and attributes are untouched. A reader of a manifest without the
    fields takes only the two exact pseudo-ref names as trees. `plan.get`'s `manifest_features`
    now lists `git_trees`.
  - **Git state fidelity.** A symbolic `HEAD` is its immediate target (`HEAD -> alias -> main`
    restored as `HEAD -> main`). Every object `FETCH_HEAD`, `ORIG_HEAD`, `MERGE_HEAD`,
    `CHERRY_PICK_HEAD`, `REVERT_HEAD`, `REBASE_HEAD`, `AUTO_MERGE`, the `BISECT_*` files and a
    rebase's, `am`'s or sequencer's state name is packed (a fetch with no destination ref lost its
    commit). A nested repository whose name is not UTF-8 is carried whole (it was dropped). A path
    the worktree tree leaves to the workspace class that holds something on disk and no class
    carries fails a final snap instead of being acknowledged as saved.
  - **Remotes are the user's.** Plan remotes are added only where the repository has none of that
    name and never change an existing URL. A resumed or recovered disk keeps its remotes (recovery
    replaced a user's changed `origin` before saving it).
  - **Recovery binds to the capture it materialized.** A recovery boot without staging that
    continues the head resumes the disk only when its recorded materialize (capture id, executor,
    epoch) is exactly the plan's head and not from a later epoch. It used to compare the worktree
    tree alone. A disk materialized by an older daemon has no record and is refused.
  - **`sealantd boot --recovery`, and one daemon per disk.** `--recovery` is `SEALANT_RECOVERY=1`
    as a flag, for a still-running MicroVM whose daemon exited (Core's agent spawns it with the same
    boot environment). Every capture boot holds an exclusive lock on `<worktree>/.sealantd/boot.lock`
    for its lifetime; a second boot on the same disk exits 75 and touches nothing. Recovery exits 0
    only when its final flush is complete, else 75.

- 9ba106d: The fourth adversarial review's daemon findings (#2, #3, #4, #7, #8, #11), and the executor side
  of cross-repo decisions 11 and 12.

  - **The working tree is read from disk, not from the user's index shortcuts (#2).** The scratch
    index a snap stages into drops `assume-unchanged`, and `skip-worktree` for every path on disk,
    so an edit behind either is captured (it restored the committed bytes, or never completed).
    Every git the capture runs gets `core.ignorecase=false`, `core.fsmonitor=false`,
    `core.untrackedCache=false`, `core.checkStat=default` and `core.trustctime=true` through
    `GIT_CONFIG_COUNT`: a distinct `A` beside a tracked `a` is captured on a case-sensitive disk
    whatever the repository's `ignorecase`. The scratch copy keeps the real index's mtime. The
    user's `.git/index` and `.git/config` are never written.
  - **Short object ids in operation state (#3).** Every run of 4–64 hex digits in `FETCH_HEAD`,
    `ORIG_HEAD`, the pending pseudo-refs and the rebase/`am`/sequencer directories is resolved as
    git resolves it (`cat-file --batch-check`), and what resolves to one object is packed. What an
    operation needs to go on — each line of `MERGE_HEAD`, `CHERRY_PICK_HEAD`, `REVERT_HEAD`,
    `REBASE_HEAD`, `AUTO_MERGE`, `BISECT_HEAD`, `BISECT_EXPECTED_REV`; the operand of a todo
    list's `pick`/`reword`/`edit`/`squash`/`fixup`/`drop`/`revert`/`merge -C` lines; `onto`,
    `orig-head`, `stopped-sha` and the other single-id files — must resolve to exactly one: a
    missing or ambiguous one fails the final snap (`snapshot-failed`), never complete.
  - **A store that cannot hold what a capture holds never completes (#7, decision 12).** A
    `plan.get` answer whose `manifest_features` leaves out one this build writes (`git_trees`
    above all) no longer downgrades silently: captures still ship, but every final flush answers
    `incomplete_reason: "store-fidelity"` (new reason code) and seals nothing. A re-plan takes the
    new registrar's features.
  - **A captured `.git/config` is authoritative (#8).** Plan remotes seed only a base: an empty
    chain, or a capture without `.git/config`. A fresh executor no longer adds back a remote the
    user removed. `MaterializeReport::git_config` says whether a materialize restored one.
  - **The final flush's sweep covers the machine on a MicroVM (#4).** `SEALANT_SWEEP_EXEMPT_FILE`
    (Core's agent: `{"version":1,"exempt":[{"pid","startTime","role","descendants"}]}`) makes a
    daemon that is not PID 1 sweep every process but its ancestors, its own helpers and the listed
    live processes (pid and start time must both match; descendants only when listed with them).
    An unreadable list is `sweep-unavailable`. A recovery boot that is not PID 1 and has no list is
    always `sweep-unavailable`: the dead daemon's orphans are the agent's, out of its descendants.
    Stopping the workspace daemon's containers through the Engine API is not undone by a restart
    policy (tested against a disposable dind).
  - **The launch from the first `plan.get` (#11, decision 11).** `SEALANT_CAPTURE_LAUNCH_ID` (new)
    names the launch; the request carries `launch` (else the launch the disk last served), a plan
    answering another `executor` refuses the boot, and a disk's staging continues the chain across
    an epoch change only for the launch that staged it (`last.json` records it).
  - **Refusals that pause, never adopt (Mend round 4).** `plan.get` 409 `worktree-leased` is
    `RegistrarError::WorktreeLeased` (it read as a wrong parent and failed the boot): a boot waits
    and asks again, touching nothing, and a re-plan keeps its identity. A heartbeat's `lease-lost`
    pauses the harness at once (it waited for the lease TTL). `upload.urls` and `capture.register`
    `lease-lost` pause shipping with everything staged under its epoch, as before, now tested per
    call.
  - **Nothing to save: never materialized (sixth end-to-end run).** A recovery boot on a disk the
    daemon before it never materialized (it died at `plan.get`) exits **76** instead of 75, after
    verifying under the disk lock and before dialling anything that the worktree is absent or holds
    nothing but the empty `.sealantd/boot.lock`: no materialize record, no staging, no capture
    state, no repository, no file. stderr says `nothing to save: never materialized`. Every other
    disk a recovery cannot save is still 75, so a platform may release exactly the 76 executors.

- 15c6640: The fifth adversarial review's daemon findings (#2, #5, #6, #11), and the executor side of
  cross-repo decisions 15 and 16.

  - **A capture runs none of the user's code; a seal is written only over the disk as it is (#2,
    decision 15).** Every git the capture runs empties each filter driver the configuration defines
    (`clean`, `smudge`, `process`, `required=false`) and sets `core.hooksPath=/dev/null`: a clean
    filter that wrote a file git had already indexed changed the disk under a final flush that went
    on to seal it. A path a filter's attribute names is read as its bytes on disk (in
    `worktree_tree` too); a restore of a capture without `raw_tree` still smudges. Before staging
    the seal, the final flush settles the watcher (a fence through its event stream) and checks
    that nothing changed since its first snap; when something did it snaps every class again (three
    rounds at most), and a disk that keeps changing answers `incomplete_reason: "changed"` with no
    seal. `capture.status` reads the same predicate.
  - **No user code over a store that cannot hold what a capture holds (#5, decision 16).** A
    `plan.get` whose `manifest_features` leaves out one this daemon writes refuses the boot right
    after `plan.get`, before the materialize — no dotfiles, lifecycle step, harness, exec or
    session — and the daemon exits **78** (`EX_CONFIG`, `EXIT_STORE_UNFIT`, log
    `outcome="store-unfit"`): nothing materialized, nothing ran, nothing saved. A standby's
    `capture.replan` onto such a store answers `policy-denied` with detail
    `{"reason":"store-unfit","unread":[…]}`, touching nothing. A recovery boot is not refused (it
    admits no writer); its final flush says `store-fidelity` and it exits 75.
  - **A symlink is a symlink, whatever `core.symlinks` says (#6).** The capture's git runs with
    `core.symlinks=true` (and `core.safecrlf=false`): a regular file that replaced a tracked symlink
    under `core.symlinks=false` restored as a symlink to its own content. A tree path whose kind on
    disk is not the tree's is named (`Captured::changed_kind`) and fails a final snap
    (`snapshot-failed`), never silently left out of the metadata.
  - **Cross-class hardlinks are only promised when they can be kept (#11).** A link names a bulk
    member only while its stat is the one the last bulk snap read; one that changed since waits for
    a small snap after a bulk snap, which a final flush takes (`snapshot-failed` while a link is
    still left out). A sealed final capture restored whole applies its links strictly: a member
    missing, not a file or holding other bytes fails the materialize (`LinkUnfulfilled`) instead of
    passing with two inodes.

- ed744a9: The sixth adversarial review's daemon findings (#1, #2, #7), and the executor side of cross-repo
  decision 17.

  - **No filter driver of the user's runs in a capture, whatever its name (#1).** The capture
    emptied every filter driver the configuration defines, but read the names lossily: a driver
    named `raw\xff` became `raw\u{fffd}`, and the user's `raw\xff` clean filter still ran after the
    final flush had stopped every writer. It left a process behind that wrote after the flush
    answered complete and sealed. The overrides are now the driver's bytes, and git is asked again
    under them: a driver left with a command or `required` on, or a configuration that cannot be
    read, fails the git before it runs (a final flush over it is `snapshot-failed`). A final flush
    also takes a census before it seals: a descendant of the daemon alive after the writers stopped
    is killed and the classes are snapped again; one found on the last of three rounds answers
    `incomplete_reason: "processes-remain"` with no seal.
  - **A write through another name of a file is captured within the cadence (#2).** A write
    through a bulk-class name of a tracked file dirtied only the bulk class, and a write through a
    name outside the workspace dirtied nothing: the old bytes stayed the capture for any number of
    intervals. An event on one name of a multi-link file now dirties every class holding a name; a
    multi-link file with names in both classes, or names neither holds, is stat'ed on its class's
    maximum interval; and a watched class with nothing pending is snapped on its reconcile interval
    (`Cadence::reconcile` 60 s, `bulk_reconcile` 600 s), a snap that stages nothing when nothing
    changed.
  - **The raw tree holds every file's bytes (#7).** An ignored `.gitattributes` still converts, but
    the raw tree was hashed only when an attribute file was among the index entries: a CRLF file
    under an ignored `*.txt text` was sealed and restored as LF. Every regular file is now hashed
    raw (cached by stat).
  - **Where an answer stands (decision 17).** `CaptureStatusReport` gains fields 27–30: `launch`
    (the executor `plan.get` named), `boot_id` (random per daemon process), `boot_generation` (the
    daemon processes that opened this disk's staging directory, persisted before the first answer;
    0 when it could not be) and `observation` (strictly increasing within one boot over every answer
    and every seal, the answer computed under it). A final seal carries `boot_id`,
    `boot_generation` and `observation` too. Same `(epoch, launch, boot_id)`: order by
    `observation`; same `(epoch, launch)` with different boots and generations above 0: by
    `(boot_generation, observation)`; anything else is incomparable. Control planes order evidence
    by this, never by their wall clocks, and fail closed on incomparable or contradictory evidence.
  - **A key the bucket already holds is uploaded (decision 19).** `upload.urls` answers such a key
    in `present` (Mend verified its bytes and mints no URL for it); the executor used to take a key
    without a URL as an error and never registered the capture. It now takes a `present` key, like
    a PUT answered 412 under `If-None-Match: *`, as already uploaded and goes on. A key answered in
    none of `urls`, `multipart` and `present` is still an error.

- 81d7017: The seventh adversarial review's daemon findings (#1, #2, #10) and the executor side of
  cross-repo decision 20.

  - **A symbolic ref stored as a symlink stays one (#1).** With `core.preferSymlinkRefs=true` git
    stores a symbolic ref (`HEAD` included) as a symlink whose link text is the target's name. The
    capture read regular files only: a sealed restore brought `refs/heads/alias -> refs/heads/main`
    back as a direct ref, and a dangling one not at all. `symrefs` now holds every symlink git reads
    as a symbolic ref, by its link text (dangling, chained, names that are not UTF-8), and a
    symlinked `HEAD` is its link text. How it was stored is kept too: the workspace class carries
    the symlink itself (link text and mtime), which the restore puts back after the git class wrote
    the ref as text. A restore over a symlinked `HEAD` replaces the link instead of writing through
    it into the branch it names.
  - **The `.git` and harness roots keep their mode and mtime (#2).** The restore wrote what is
    under them and left both `0777` under the umask with the time of the restore. Both are now set
    from the workspace class's root entries last of all.
  - **One inode, one mode, one mtime (#10).** A strict restore of a sealed capture refuses, before
    it changes anything, a worktree metadata document that promises names of one inode (a hardlink
    group, a shared link, a cross-class group) different modes or mtimes
    (`MetaError::InodeConflict`). The writer never emits one: a final snap that reads an inode
    moving between two of its names fails (`snapshot-failed`, no seal); any other snap gives every
    name the first name's metadata and the next snap takes the change.
  - **`present` is negotiated (decision 20).** Every `plan.get` request carries
    `"upload_answers":["present"]` (`registrar::UPLOAD_ANSWERS`). A registrar answers `present`
    only to an executor whose `plan.get` listed it, and a conditional URL (whose 412 every daemon
    takes as uploaded) to one that did not: an older daemon, like the binary on a retained disk,
    failed on `present` with `no url` on every retry.

- 5fdec3e: The eighth adversarial review's daemon findings (#1, #2, #3, #10) and the executor side of
  cross-repo decisions 22 and 23.

  - **A root reached through a symlink is read through it (#1).** A `.git` moved beside the
    worktree and linked back, or a harness home configured as a link, was listed as nothing: its
    bookkeeping (`config`, `MERGE_MSG`) or transcript was missing from a sealed restore. Roots are
    now walked through the link (the link text rides `workspace.root_links`), and a root that is
    not a directory at all makes a final flush `unreadable` instead of an empty listing.
  - **A symlinked `FETCH_HEAD` or operation document keeps what it names (#2).** The collector read
    regular files only; it now reads through the link as git does, and one it cannot read makes a
    final flush `snapshot-failed`.
  - **A symlink with several names makes a final flush incomplete (#3, decision 23).** No class
    carries one inode for a symlink's names; a final flush over one fails naming it instead of
    sealing two separate symlinks.
  - **SHA-256 repositories (#10).** The git section names a format that is not SHA-1
    (`object_format`, a new manifest feature) and the restore initializes its repository with it
    before any pack goes in. A store that does not read `object_format` gets no complete final flush
    of a SHA-256 repository.
  - **Complete only on a recorded seal (decision 22).** `capture.register` answers
    `seal: {state: "recorded" | "withheld" | "refused", reason?}` for a capture carrying
    `final_seal` (on a lost ack too). A final flush is complete only on `recorded`; `withheld` is
    asked again by re-sending the same register (bounded), and still withheld, refused or not said
    answers `sealing`.

- 4670120: The ninth adversarial review's daemon findings (#1, #2, #3 and the executor side of #7), and
  cross-repo decision 24.

  - **Git state is read through git (#1, decision 24).** `HEAD`, the refs, the reflogs and the
    root refs are read with backend-aware git (`symbolic-ref --no-recurse`, `rev-parse`,
    `rev-list --reflog --stdin`, `for-each-ref --include-root-refs`), never from `.git/HEAD` or a
    `logs/` directory. In a reftable repository the `HEAD` file is `ref: refs/heads/.invalid` and
    there is no `logs/`: a commit only its reflog, its detached `HEAD` or its `ORIG_HEAD` reached
    was left out of a sealed capture, and a cold restore lost its file. The git section names the
    backend (`ref_format: "reftable"`, a new manifest feature, absent for `files`); the restore
    initializes the repository with it and writes the refs through git. A store that does not read
    `ref_format` gets no complete final flush of a reftable repository.
  - **A ref symlink comes back as a symlink (#2).** `.git/refs/heads/alias -> main` (git reads the
    file it reaches) was dropped from the workspace class because its text is not a ref name.
    Every symlink under `.git/refs/` and at `.git/HEAD` is carried now, and the restore writes the
    ref file its chain ends on loose again so it resolves. One that reaches outside the repository
    makes a final flush `snapshot-failed`.
  - **Times past 2262 (#3).** A modification time outside signed 64-bit nanoseconds saturated and
    sealed. A final flush over one (any class, directories too) is `unreadable`, naming the path.
  - **Hardlink groups with different bytes (#7).** A strict restore refuses to relink a tracked
    hardlink group whose names hold different bytes; a lenient one leaves them apart.

- 55a9261: A small capture no longer waits for a bulk capture's upload, and `capture.status` gains
  `pending_bulk` (daemon behaviour plus one additive wire field).

  The capture chain is linear, and a bulk capture (a dependency tree) was an ordinary link in it.
  On alpha a session's `pnpm install` left about 800 MB of `node_modules` in about 20k objects,
  which took the shipper twenty minutes to upload. Every small capture staged after it named it as
  its parent and waited behind it, so the agent's edits never registered while it uploaded:
  `capture.flush` timed out or answered `pending 5`, and the checkpoints the control plane derived
  read `0 files · +0 −0`. The engine now stages a small capture ahead of a queued bulk capture that
  is still uploading. The small capture takes the bulk capture's place on the chain with the bulk
  section it was staged on (or `"pending"`), and the bulk capture moves on top of it with the same
  objects and a new manifest. The shipper uploads a bulk capture's objects without claiming it and
  stops between objects when a capture is staged ahead of it or a flush is waiting. `capture.flush`
  returns once every capture ahead of the bulk capture is registered, and the bulk capture keeps
  uploading in the background. `capture.status` reports it in `pending` and in the new
  `pending_bulk` field (`CaptureStatusReport.pendingBulk`), so a caller reads
  `pending == pending_bulk` as flushed. A `final` flush still spends what is left of its deadline
  on the bulk capture.

  A flush also used to run its ship pass beside the worker's over the same objects. Each pass took
  the PUT URLs the other had minted, the losing pass minted one key per `upload.urls` call, and the
  registrar's call quota answered 429, reported as `no url for …/trees/<sha>` and never retried.
  One pass runs at a time now. A 429 or 5xx from `upload.urls` is a transient failure and is
  retried, a failed batch mint is retried as a batch rather than one call per key, and URLs minted
  in the last five minutes are reused instead of minted again.

### Patch Changes

- f7feb5a: Five findings of the second Docker end to end (daemon-only; no wire change).

  - The reply to a final `capture.flush` reaches its caller. In Docker, Core reaches the control
    socket through `docker exec … socat`, and the final flush's sweep of the PID namespace stopped
    that `socat`, so every stop saw "connection closed". The sweep now spares the process at the
    far end of a live control connection (`SO_PEERCRED`) and its ancestors, unless sealantd
    started or adopted it.
  - The workspace's own Docker containers stop before the processes, then are checked again: a
    process streaming a container's output into the worktree (`docker logs -f > file`) no longer
    loses the tail, and a container a process starts on its way out is stopped.
  - Nothing snaps on a schedule once a final flush stopped every writer, and a preempted scheduled
    bulk build no longer resumes after the forced one. `capture.status` reports `complete: false`
    (`pending`) while a bulk capture is being built after the final one.
  - A restore keeps the directory mtimes that linking a bulk name onto a tracked inode moved:
    `node_modules` and a pnpm `file:` package's directories.
  - The paths a materialize removes are logged at debug. On a fresh executor they are
    `git init`'s template files, never work product (see the capture README).

- a775b6e: Three findings of the fourth Docker end to end (daemon-only; no wire change).

  - A session's first executor gets the fast repeat final flush. Its `pnpm install` runs after
    sealantd boots, so there was no bulk directory at boot and the bulk class polled for the
    executor's life: every final flush after a complete one walked the dependency tree again
    (~2.5 s; a Stop took ~15 s, not 6–7 s). The bulk class is watched with no bulk directory yet,
    and one made later gets its watches then, within the budget (past it, the bulk class polls). A
    directory too long to name to `inotify_add_watch` is watched through its opened descriptor
    (`/proc/self/fd/<fd>`) instead of making its class poll.
  - A suspend flush after a complete final flush stages nothing. Mend's Stop sent two after
    `sealantctl capture flush --final`; each staged a `suspend` capture of the same tree, the final
    flush after them snapped nothing and sealed nothing, and the head read `suspend`. Over the disk
    the final flush captured, a suspend flush is a status read. Anything staged after the final
    capture all the same (a turn boundary) turns `complete` false (`pending`), and the next final
    flush seals the chain with a final capture before it says `complete`.
  - A failing snap names what it did and where: `write /…/.sealantd/capture/index/last.tmp: No
space left on device (os error 28)`, not the bare `No space left on device (os error 28)`, in
    `snaps[].last_snap_error` and the flush's error. A final flush whose small snap failed takes no
    bulk snap (it is incomplete whatever that does; each one on a kept executor walked the
    dependency tree for 2.4 s more).

- 6ef5892: The fifth Docker end-to-end run's daemon findings.

  - **The shutdown's final flush has a deadline: `SEALANT_SHUTDOWN_FINAL_DEADLINE_MS`.** With the
    object store down, the `SIGTERM` final flush retried forever: the executor ran until the
    platform's stop timeout killed it, and the exit-75 path ("keep my disk, recover it") was never
    reached. When the variable is set, a shutdown's final flush (`SIGTERM`, `SIGINT`,
    `runtime.gracefulShutdown`) takes at most that many milliseconds from the shutdown. That
    includes waiting for a final flush already running. The daemon then exits 75 with its staging
    directory as it was. The platform should set it to its stop grace less a margin (at least 5 s).
    Unset, the flush runs until it completes, as before. `sealantd` also takes it as
    `--shutdown-final-deadline-ms`.
  - **Retries spend no mint calls.** A minted PUT URL is used again until the upload of its key
    settles or the URL is five minutes old, and a multipart upload resumes under the same upload.
    Every retry used to mint again, and a store that stayed down ran the registrar's `upload.urls`
    call quota out (560 calls in three minutes). A pass that fails on a transient refusal
    (unreachable, 5xx, 429) now waits 1 s before the next one, doubling to 30 s.
  - **The exit code follows the daemon's own last final flush.** A sealed, complete executor exited
    75 because its exit decision re-read the live status, which a final flush queued behind its own
    had just reset to `in-progress`. On the review-3 head, a class that polls also made every final
    flush answer `changed`, so a daemon whose bulk class polled could never exit 0. A final flush
    now answers complete when its own snaps (taken after every writer stopped) captured every class,
    a polled one included. `capture.status` read later reads `incomplete_reason: "unwatched"` (new
    reason code) while a class polls, since nothing vouches for it after the flush.
  - **A dependency install no longer turns watching off.** A directory renamed or removed before
    its watch was added (`pnpm` unpacks into `<name>_tmp_<pid>_<n>` and renames it into place) made
    the bulk class poll for the executor's life: about 750 MB went uncaptured for minutes after
    `pnpm install`, and every repeat final flush walked the tree again. Such a directory is not a
    failure now. A directory that cannot be watched for a lasting reason has its class poll while
    the rest stays watched. It is tried again (2 s, doubling to 60 s), and once it is watched the
    class is watched again.

- d992b9f: Opening the capture no longer erases a `.git/info/exclude` that is not UTF-8 (review 12 #1).
  The daemon's `/.sealantd/` rule is appended to the file's bytes, never to a decoded copy, the
  file keeps its mode, and the update stays atomic. Only a missing file reads as empty; any other
  read error leaves the file alone. Before, a valid exclude file with a legacy-encoded byte (for
  example a Latin-1 comment) read as empty, and every user rule in it was replaced by the daemon's
  one line before the first capture.
- d992b9f: A cold restore gives back every hardlink group across classes as one inode (review 12 #2). A
  link the worktree metadata makes (`shared`, `cross_links`) now moves every name of the linked
  member's own restored hardlink group. The bulk index holds one name per group, so those links
  name only that one. Before, pnpm's peer-context copies of a local package (two bulk names of a
  tracked file's inode, made by a plain `pnpm install`) came back with one copy on an inode of its
  own, and an edit to the restored package reached only one consumer. The same applied to a
  workspace file with several bulk names. A sealed final capture restored whole now also checks,
  once every link is made, that each set of names the capture joins is one inode per filesystem,
  and fails the materialize (`LinkUnfulfilled`) if it is not.
- d992b9f: A final flush asks about a refused seal again (review 12 #4). Only a `recorded` seal answer
  outlives the final flush that heard it. A final flush over an unchanged disk that an earlier
  one heard `refused` or `withheld` sends the sealing register again at once. That is one register
  per final flush for a registrar that keeps refusing. A registrar that refused while it could not
  read the objects, and has since recovered, now gets to record the seal. Before, the daemon kept
  the first refusal, and repeated final flushes answered `sealing` without asking again.
- b81b3fc: A delta restore keeps no hardlink the capture does not hold (review 15 #2). A standby's
  `capture.replan` reuses a file whose bytes it already has, and the file kept every name its
  inode had on the standby's disk. After a standby's `pnpm install` linked a tracked package file
  into `node_modules`, a head whose source had since replaced that file with its own copy came
  back still linked: an edit to the tracked file reached the installed package, and restoring the
  tracked file's mtime changed the package's. Two tracked aliases split after a restore stayed one
  inode the same way. A whole restore now puts each group of names the capture joins, a single
  name included, on an inode of its own before it links anything: only multiply-linked files are
  checked, and only the names that must leave an inode are copied (same bytes, mode and mtime). A
  sealed final capture restored whole also fails the materialize if any inode still holds names
  of two groups.
- 1947651: A restore never consumes a user file named like its staging file (review 16 #2). The delta
  restore's hardlink split copied a file through the fixed name `.<name>.capture-apart` and the
  file writer through `.<name>.capture-tmp`, both opened with truncation: a captured user file of
  that name was overwritten and renamed onto the restored file, and the restore reported success
  without it. Staging files are now created exclusively (`O_EXCL`) under a fresh name, never over
  an existing one, and only a staging file the restore created is removed on a failure. A sealed
  final capture restored whole also fails when any file a class promised is missing afterwards.
- 7874de0: Opening capture never consumes a user file named like its git staging file (review 17 #2).
  Adding the daemon's line to `.git/info/exclude` staged the new file through the fixed name
  `.git/info/exclude.capture-tmp`, opened with truncation, and renamed it over `info/exclude`: a
  user file of that name was overwritten and renamed away at the first open and again when a
  restarted executor reopened a disk whose sealed capture held it, and the next final flush sealed
  the disk without it. The restore's `HEAD`, `packed-refs` and pack writers had the same fixed
  names (`HEAD.capture-tmp`, `packed-refs.capture-tmp`, `objects/pack/tmp-capture-<sha>.*`). All
  four now stage in a file created exclusively (`O_EXCL`) under a fresh name, and only that file is
  removed on a failure.

## 0.18.2

### Patch Changes

- edad671: Dotfiles detection, `HOME` and the arm64 loader shim (daemon-only; the packages ride the release
  train).

  `manager: auto` picked stow for any tree with a non-dot top-level directory, and stow skips
  top-level dot entries. A home mirror (`.config/`, `.zshenv`, `.gitconfig` beside `bin/`,
  `Library/`) therefore had none of its dotfiles applied and its plain directories stowed into
  `/root` instead. Auto now picks stow only for a stow layout: package directories and no top-level
  dot entries except repository and stow metadata (`.git`, `.gitignore`, `.github`, `.stowrc`, …).
  Plain top-level files such as `README.md` or `Brewfile` still allow stow. A mixed tree is copied.
  Only the top level is examined, so a `*.tmpl` deep inside a home mirror does not select chezmoi.
  A chezmoi source whose `chezmoi` binary is missing is copied rather than stowed. Boot logs the
  resolved manager and what decided it.

  An explicit `manager: stow` copies the top-level dot entries into the target before stowing the
  packages and logs their names. Before this it dropped them without a log line. The copy manager
  now recreates symlinks as symlinks, as `cp -a` does, so a dangling link no longer fails boot. It
  also replaces an existing file or link at the destination instead of writing through it.

  `chezmoi apply` (now with an explicit `--destination` and `--no-tty`), `stow`, the dotfiles clone
  and the `./install.sh` bootstrap run with `HOME`, `USER` and `LOGNAME` set to the workspace home
  and without the `XDG_*_HOME` overrides. They no longer depend on the environment the runtime
  started PID 1 with. A MicroVM's init supplies no `HOME`.

  On a Nix base the glibc loader shim links the running architecture's loader,
  `/lib/ld-linux-aarch64.so.1` on arm64 as well as `/lib64/ld-linux-x86-64.so.2` on x86-64. It
  used to look only for the x86-64 one.

## 0.18.1

### Patch Changes

- 0caa546: The released daemon image ships `sealantctl` beside `sealantd` and `socat` (image-only; the
  packages ride the release train). A Lambda MicroVM's in-VM agent runs `sealantctl capture flush`
  in the platform's suspend and terminate hooks, where no control plane is connected to ask the
  daemon for it. An image builder can now `COPY --from` the client out of the released image, as it
  does the daemon. Before this the image held no `sealantctl`, so a workspace image built from a
  released daemon could not flush its captures when its MicroVM was stopped.

## 0.18.0

### Minor Changes

- 86eaf1f: Remotes for the repository of a capture-source workspace (daemon-only; the packages ride the
  release train). `plan.get` may now answer `remotes`: per remote a `name` and a `url`. The boot
  sets each one on the worktree's repository after it materializes the head, and `capture.replan`
  sets those of the worktree it is assigned, because a standby executor boots under a placeholder.

  The executor builds that repository itself: `git init`, then the head's packs. Remotes are
  configuration of the control plane's own copy and never travel in a capture, so the repository a
  harness worked in had none, and `git push origin` or `git fetch origin` failed with "'origin' does
  not appear to be a git repository" in every captured session. Only the name and the URL travel;
  how the remote is authenticated stays with the control plane. A missing remote is added, one that
  points elsewhere is updated, and a remote the session added itself is left alone. A name or URL
  that could read as an option fails the boot; a git failure is logged and skipped. A registrar that
  answers no `remotes` is unchanged in every respect.

### Patch Changes

- The reply to `runtime.gracefulShutdown` is sent before the daemon exits (daemon-only; the
  packages ride the release train). The Unix control frontend spawned each connection and never
  joined it, so once shutdown was requested the process could exit while that connection still had
  the reply queued, and a client saw `connection closed` with its request pending. `serve_unix`
  now stops accepting, lets live connections flush and end on the shutdown signal they already
  hold, and joins them (aborting after two seconds), as the WebSocket frontend already did.

## 0.17.0

### Minor Changes

- c7efe50: The capture session channel fails closed on transport (daemon-only; the packages ride the release
  train). `sealantd` now dials `SEALANT_CAPTURE_ENDPOINT` and every presigned object URL over HTTPS
  with a verified certificate, and never falls back. An endpoint it does not dial refuses boot, before
  the session token leaves the process; an object URL it does not dial is refused when the registrar
  answers it, before a byte is sent.

  - Plain HTTP is dialled to loopback, and otherwise only when the launcher sets
    `SEALANT_CAPTURE_ALLOW_PLAINTEXT=true`: a statement that the network between the executor and the
    channel is private. **A launcher that reaches the channel over plain HTTP on a Docker, cluster or
    VPC network must set it, or boot refuses with a message naming the variable.**
  - `SEALANT_CAPTURE_CA_PEM` (inline) or `SEALANT_CAPTURE_CA_FILE` (a path) names the roots the
    channel's certificate must chain to, in place of the public roots;
    `SEALANT_CAPTURE_OBJECT_CA_PEM` / `SEALANT_CAPTURE_OBJECT_CA_FILE` do the same for object URLs.
  - Certificate and host name verification cannot be turned off, and the plaintext exception does not
    relax it.
  - No redirect is followed on the channel or on an object URL; a 3xx is reported as the answer.
  - `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` in the daemon's environment are no longer honoured on
    these two paths.
  - A refusal names the host only, never a path or query, since a presigned URL is a credential.

## 0.16.0

### Minor Changes

- d0a53fb: Content beside the worktree in a capture-source workspace (daemon-only; the packages ride the
  release train). `plan.get` may now answer `sources`: per source a name, an absolute path, the
  object key of a gzipped tar whose GET URL rides `get_urls`, the archive's `sha256`, its `bytes`
  and `read_only`. The boot fetches each one, verifies the digest, and extracts it at that path
  before the control socket binds.

  A capture-source workspace mounts nothing from the host — the executor materialises the worktree's
  head capture on its own disk — so a control plane had no way to put a directory beside the
  repository. This is how Mend's organization folders and reference repositories reach one. Three
  rules: a path inside the worktree (or one the worktree sits under) fails the boot, because content
  there would be listed by the next capture and shipped into the store as the session's own work; a
  source is a copy and never travels back, with `read_only` additionally taking the writable bit off
  the tree; and the archive's sha256 is the content stamp, so a re-materialize re-extracts only what
  changed. One source failing costs that directory and not the session — a fetch, digest or
  extraction failure is logged and skipped, extraction runs in the staging scratch directory and is
  renamed into place, and an archive past 64 MiB is skipped.

  `capture.replan` lays down the sources of the worktree it is assigned, because a standby executor
  boots under a placeholder worktree and only then learns whose session it is. A registrar that
  answers no `sources` is unchanged in every respect.

### Patch Changes

- 47e1c8e: Every PUT URL is minted for the length the PUT then sends (daemon-only; the packages ride the
  release train). `UrlMinter::put_url` takes the object's size, so the single-key fallback mint — the
  path for a key no batch minted — declares that object's real byte count instead of the `0` it sent
  before, and the git pack index's upload is sized from `fs::metadata` with the error surfaced rather
  than swallowed into a `0`. `upload.urls` already carried `sizes` for every key of a batch; these
  were the two places a key could still travel with a size that was not its length.

  Before this, a registrar that binds an upload signature to an exact content length — Mend's upload
  length binding, `MEND_CAPTURE_REQUIRE_SIZES` — would mint a URL signed for zero bytes and the
  store would refuse the body, or the declared size would simply be wrong. Both PUT paths already
  sent `Content-Length`; now the length in the signature and the length on the wire are the same
  number by construction.

## 0.15.2

### Patch Changes

- 888dc6b: Byte-quota refusals are terminal (daemon-only; the packages ride the release train). A 413, or a
  409 whose `reason` is `byte-quota`, is now `RegistrarError::QuotaRefused` with the body's `limit`,
  `used` and `requested` instead of a wrong parent (409) or a protocol error (413): the shipper drops
  that queue entry with its staged bytes and every queued capture that descends from it, logs the
  capture's `n`, class and the numbers, and marks the class `refused` in `capture.status` (a new
  `refused` field, one `CaptureClass` per refused class). A refused bulk class takes no further snap
  until the next epoch or `capture.replan`; the small class keeps snapping and shipping, and the
  engine continues the chain from the refused capture's parent, forgetting the chunk locations of
  packs that never went up. Before this, neither status dropped the entry, so the ship worker re-ran
  the same refused call every 5 s for good (observed on the cluster: a 775 MB bulk capture uploaded
  in full, then `register n=4: … http 413` on every tick). `upload.urls` also carries `sizes` for
  every key of a batch, not only multipart-sized ones, so the registrar can price a whole batch
  before it mints a URL.
- fa65ce0: The orphan reaper now reaps only pids the daemon did not spawn. sealantd runs as PID 1 / child subreaper, and its reaper peeked every waitable child and reaped whatever the process registry did not list — so the capture engine's blocking `git` children (`rev-list`, `pack-objects`, `index-pack`, and since 0.15.1 `head_tree` and `stored_tips`), the PTY/pipe session leaders and the boot helpers, none of which were registry-owned, could be reaped mid-sweep and their own `wait()` failed with `ECHILD`: "No child process (os error 10)". A `capture.flush` that landed on the same SIGCHLD as the harness command's exit was refused that way (Mend 0.27.3's amd64 acceptance; reproduced in 1 of 8 runs on a 2-CPU daemon). Ownership now lives in a process-wide spawned-pid gate (`sealant-process/src/spawn.rs`) that every daemon-internal spawn goes through and the reaper holds for a whole sweep; a pid is released the moment its spawner has reaped it. Adopted orphans are still reaped exactly as before.

## 0.15.1

### Patch Changes

- 6dd17a9: Capture store fixes from the first real cluster session (daemon-only; the packages ride the release
  train). Tracked always wins: the workspace-class sweep no longer removes `.git/index` when the plan
  does not carry one (a control-plane base has an empty workspace class), and the worktree tree is
  seeded from `HEAD` when no index is on disk, so a tracked file that matches `.gitignore` (`core.*`
  against `tooling/core.json`) stays in the tree instead of showing as deleted. The seed after a
  materialize records only what the chain holds (refs, `HEAD`, reflog), not freshly written index and
  worktree trees, so the next pack carries every subtree the disk differs by (was `fatal: unable to
read tree` on the next capture). An unchanged `auto` snap no longer deletes staged objects a queued
  capture still lists (was a ship loop stuck on `upload …/trees/<sha>: no GET url in plan` behind a
  long bulk upload); a snap coalescing a queued capture of the other class carries its dir objects.
  The shipper mints PUT URLs in batches of 500 through one `upload.urls` call instead of one call per
  object, and `.rev` files `git index-pack` leaves beside packs are removed.

## 0.15.0

### Minor Changes

- 3e232b7: `capture.replan` joins the protobuf `Command` oneof and the generated TypeScript, answered by
  `CaptureReplanned` (worktree, epoch, head, files and bytes written versus skipped, removed,
  `unchanged`). A standby executor boots on the project base under a placeholder worktree; once
  the control plane assigns it a worktree, `capture.replan` fetches the plan again, materializes
  the chain head as a delta over the disk, takes the worktree id and lease epoch the plan names,
  drops captures staged under the placeholder, and resumes the cadence — so a hot-pool standby
  serves joins and pickups without a cold materialize. Idempotent when the plan names what the
  executor already has. The daemon also sends its `platform` on `plan.get` and honours a
  `"pending"` bulk answer (another platform's dependency tree is not restored).

## 0.14.0

### Minor Changes

- 20dd27b: Capture-store control commands (ADR-0015): `capture.now { kind }`, `capture.flush`,
  `capture.status` and `lease.epoch` join the protobuf `Command` oneof and the generated TypeScript,
  so a control plane can force a whole-workspace capture ahead of the daemon's cadence, flush staged
  captures before a planned stop, read the capture runtime's state, and rotate the lease epoch. The
  daemon also boots from a `capture` workspace source (`SEALANT_WORKSPACE_SOURCE=capture`), which
  materialises the worktree from the session channel onto local disk and ships captures back.

## 0.13.0

### Minor Changes

- c18aa16: `bindMount { mountPath, subpath }` (ADR-0014): point a bindable mount's path at a subdirectory of
  its root, or unbind with an empty subpath. Boot reads `SEALANT_BINDABLE_MOUNTS` and `SEALANT_BINDS`,
  and `SEALANT_WORKSPACE_SOURCE=standby` makes the working directory itself bindable. The client gains
  `bindMount(mountPath, subpath)`.

## 0.12.0

### Minor Changes

- 633dbcd: Daemon: opt-in mutual-TLS WebSocket control frontend (ADR-0013). `SEALANT_CONTROL_WSS_LISTEN`
  (boot) / `--wss-listen` (bare CLI) serve the unchanged length-prefixed Protobuf control protocol
  over `wss://…/control` beside the Unix socket — rustls with `WebPkiClientVerifier` and no anonymous
  fallback, so no certificate, a foreign CA, or a serverAuth-only certificate fails the handshake
  before any HTTP byte is read. With the new variables absent the daemon behaves exactly as before.

## 0.11.0

### Minor Changes

- 813ee8e: Pipe-mode sessions: `openSession` accepts `mode: SESSION_MODE_PIPE` to start the leader with plain
  stdio pipes and no controlling terminal — for processes that speak a byte protocol over stdio
  (JSON-RPC / NDJSON servers). stdout is the journaled, attachable output with the same reattach and
  tombstone semantics as PTY sessions; stderr is recorded as telemetry only; `writeStdin` feeds stdin;
  `resizePty` is rejected. `SessionSummary.mode` reports the shape and `FeatureMatrix.pipeSessions`
  advertises support. Unspecified `mode` still means PTY.

## 0.10.0

### Minor Changes

- 8c2d31e: Launcher-provided secret environment: `sealantd boot` accepts a new `SEALANT_SECRET_ENV_FILE`
  input — a JSON object (`name → value`) read exactly once at boot. Its entries are injected into the
  harness child environment explicitly (they bypass the daemon's secret-name scrub, override
  same-named passthrough entries, and can never set the boot-owned `HOME`/`USER`/`LOGNAME`/`PATH`),
  and every value seeds the I/O redactor regardless of its name, so a workspace can receive
  `DATABASE_URL`, `STRIPE_API_KEY`, and friends without them ever riding container env, `docker
inspect`, or captured output in the clear. Names are grammar-checked and must not be
  `SEALANT_`-prefixed; a malformed or unreadable file fails boot loudly (parity with dotfiles
  archives). The launcher is expected to remove the file once the workspace reports ready — from then
  on the values live only in daemon memory and child environments. The `configHash` fingerprint
  logged at readiness now covers the sanitized configuration (env keys, never values).

## 0.9.0

### Minor Changes

- fde1a2a: Runtime dotfiles hardening + caller-provided archives: `sealantd boot` now applies dotfiles BEFORE
  the control socket binds (readiness-gated injections like credential files can no longer race a
  dotfiles apply into `$HOME`), `SEALANT_DOTFILES_REPO_REF` is optional (absent clones the remote's
  default branch instead of assuming `main`), and a new `SEALANT_DOTFILES_ARCHIVE_DIR` input applies
  caller-staged gzipped tars (`manifest.json` + `<n>.tar.gz`, per-archive manager/target/bootstrap)
  through the same chezmoi/stow/copy dispatch — the transport for dotfiles resolved host-side with
  the caller's own ssh identity or scanned from a home directory. Archive apply failures abort boot
  like the repo path.

## 0.8.0

### Minor Changes

- d195113: Custom-base support: `sealantd boot` accepts `SEALANT_OS_FAMILY=custom` (tool paths fall back to
  `/bin/sh` — the custom-base contract guarantees a POSIX shell and nothing more), and the sealantd
  image now ships a fully static `socat` at `/usr/local/bin/socat` beside the daemon, so workspace
  image builders can `COPY --from` the control-relay dependency into any base instead of depending
  on the base's package manager.
- d195113: `sealantd boot` accepts `SEALANT_OS_FAMILY=ubuntu` (Ubuntu workspace images boot with
  fedora/arch-style tool-path defaults; the glibc loader shim stays Nix-only). The unknown-value
  error now lists `fedora|arch|nix|ubuntu`.

## 0.7.0

### Minor Changes

- 12c9a3f: UDP forwards: `openForward` accepts `protocol: "udp"` and opens a connected
  UDP socket instead of a TCP stream. The channel is already message-framed, so
  one frame is exactly one datagram in both directions — boundaries hold end to
  end. Omitted or `"tcp"` keeps the existing byte-stream behavior; the wire
  field is absent for TCP, so old daemons and clients interoperate unchanged.

### Patch Changes

- 12c9a3f: End interactive terminal attachments when their session leader exits, even if a helper process
  inherited the PTY slave and keeps it open. Sealantd now drains output already written by the leader,
  emits the final stream end immediately, and releases the PTY master instead of making clients wait
  for unrelated helper cleanup.

## 0.6.2

### Patch Changes

- c211894: End interactive terminal attachments when their session leader exits, even if a helper process
  inherited the PTY slave and keeps it open. Sealantd now drains output already written by the leader,
  emits the final stream end immediately, and releases the PTY master instead of making clients wait
  for unrelated helper cleanup.

## 0.6.1

### Patch Changes

- f0a6d8b: Keep platform-injected harness credentials in the harness environment. The boot passthrough scrub
  dropped every env var that looked like a secret — including `CLAUDE_CODE_OAUTH_TOKEN`, `GITHUB_TOKEN`,
  and `GH_TOKEN`, which the control plane injects into the container precisely so the harness can use
  them. Those contract keys now survive the scrub, and injectors can exempt further keys by declaring
  them in `SEALANT_HARNESS_ENV_KEYS` (comma-separated). Consumed `SEALANT_*` keys can never be exempted.

## 0.6.0

### Minor Changes

- ce1ade7: Mount-based workspace provisioning, durable interactive PTY sessions, and default-on file watching.

  - **Protocol**: `AttachSessionArgs.fromSequence` (journal replay before live frames), new
    `signalSession` and `readSessionOutput` commands, `SessionOutput`/`SessionOutputChunk` results,
    and `SessionSummary` lifecycle fields (`state`, `exitCode`, `signal`, `startedAtMicros`, journal
    cursor bounds).
  - **Client**: typed `openSession` / `closeSession` / `resizePty` / `listSessions` /
    `signalSession` / `readSessionOutput`, `attachSession(id, { fromSequence })` for
    reattach-with-scrollback, and buffering of stream frames that arrive ahead of the response
    carrying their channel id (journal replay does this by design).
  - **Daemon**: workspaces can be provisioned from a caller-owned bind mount
    (`SEALANT_WORKSPACE_SOURCE=mount` + operator allowlist `SEALANT_MOUNT_ALLOWED_STORE_ROOTS`) with
    the mounted contents never touched by any lifecycle event; PTY output is redacted and journaled
    to disk per session (replayable from sequence 0, retained across client disconnects and after
    exit); `SEALANT_WATCH_FILESYSTEM` now defaults on, with ignore-pruned per-directory watch
    registration and file events stamped with the active execution id.

## 0.5.1

### Patch Changes

- 21cf300: Boot clone honors the repository's default branch when no ref is given. `SEALANT_WORKSPACE_REPO_REF` is now optional (missing or empty means "the remote's default branch"): the boot clone only passes `--branch` when a ref was explicitly provided, so a plain `git clone` resolves the remote HEAD. Previously the env var was required and the control plane injected `main`, which broke every repository whose default branch isn't `main` (e.g. `master`) with `fatal: Remote branch main not found in upstream origin`.
- 4d91f06: The orphan reaper can no longer steal a Tokio-owned child's exit status. Spawn paths (exec, sftp bridge) now register their child's pid in an owned-pid set under a shared spawn↔reap lock, and the reaper holds that lock for its whole sweep — closing the race where a fast-exiting child (e.g. `printf`) was reaped as an "adopted orphan" before its ownership was recorded, surfacing as `process.exited` with `exit_code: null` (the intermittent `binary_stdio_roundtrips_binary_unsafe_output_and_shuts_down` CI failure).

## 0.5.0

### Minor Changes

- f0c4c08: Rename the "sandbox" concept to "workspace" everywhere (breaking, coordinated with the core monorepo — no backwards compatibility).

  - Wire: proto field `sandbox_id` → `workspace_id` (field number 3 unchanged); regenerated `sealant_pb.ts` so the embedded descriptor carries the new field name.
  - Client SDK: `sandboxId` option → `workspaceId`, passing `--workspace-id` to the daemon.
  - Daemon contract: env vars `SEALANT_SANDBOX_*` → `SEALANT_WORKSPACE_*`, CLI flag `--sandbox-id` → `--workspace-id`, container root `/sandbox` → `/workspace`, SSH username prefix `sbx-{id}` → `ws-{id}`.

## 0.4.1

### Patch Changes

- cbacf43: Update repository metadata for the GitHub org rename: `get-sealant` → `sealant-sh`. The npm
  packages and their APIs are unchanged; this refreshes the `repository` URLs (and the image
  namespace referenced in docs) so npm and registries point at the new org.

## 0.4.0

### Minor Changes

- c278703: TS SDK: regenerate off the updated proto + add channel-multiplexing client support (gateway substrate)

  - `@sealant/runtime-protocol`: regenerated the protobuf-es output from `sealant.proto` so the byte-conduit surface is now in the SDK — `StreamFrame`/`StreamWindowUpdate`/`StreamEnd`, `ClientMessage::Stream` + `ServerMessage::Stream`, the channel commands (`attachSession`/`detachSession`/`openForward`/`closeForward`/`openSftp`/`closeSftp`) and their results (`StreamAttached`/`ForwardOpened`/`SftpOpened`/`ProcessAttached`), the `AttachMode` enum, and `ExecArgs.attach`. These new types/enums/schemas are explicitly re-exported from the package index, plus a new `asStream(ServerMessage)` narrower and an `encodeServer(ServerMessage)` codec (symmetric with `encodeClient`/`decodeServer`).
  - `@sealant/runtime-client`: added channel support a multiplexing consumer (the gateway's SSH channels) builds on, with the existing API kept intact. The client now demuxes inbound `ServerMessage::Stream` frames by `channel_id` into per-channel `Channel` sinks (an async-iterable of inbound `Uint8Array` bytes with `write`/`windowUpdate`/`end`/`closed`), and muxes outbound bytes back as `ClientMessage::Stream` frames. New methods: `openChannel(channelId)` (low-level register), `attachSession`/`detachSession`, `openForward`/`closeForward`, `openSftp`/`closeSftp`, and `execAttached` — each opener returns `{ result, channel }`. `StreamEnd` closes only its own channel; a dropped connection fails all open channels.

## 0.3.0

## 0.2.0

## 0.1.3

### Patch Changes

- d9a57f8: Validate the release pipeline after renaming the publish environment to `release`. No API or runtime changes.
