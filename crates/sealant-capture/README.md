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
directories of a `"pending"` bulk section. Each removed path is logged at debug
(`materialize: removed …`); `removed` in the `capture head materialized` line counts them.

On a fresh executor that count is not zero, and what it counts is `git init`'s template, never
work product. The materializer creates the repository with a plain `git init`
(`GitRepo::init`), which writes `.git/hooks/*.sample` (14 with git 2.43, the Ubuntu workspace
image; 13 with Debian's 2.39), `.git/description`, `.git/config` and `.git/info/exclude`. The
workspace class lists `.git/` bookkeeping, and no captured disk holds the samples or
`description` (the first executor's materialize removed them before its first snap), so every
later fresh boot removes exactly those 15 (`removed=15` in the Docker end to end, from heads 17
to 67). The executor that boots on a control-plane base capture (an empty workspace root)
removes 17: `config` and `info/exclude` too, which sealantd writes again right after
(`info/exclude` with `/.sealantd/`, `config` by `remotes::apply`); the template's `config` holds
only git's built-in defaults for a non-bare repository. `GitRepo::exclude_locally` appends its
rule to `info/exclude` as bytes, never decoding the user's file (a legacy-encoded comment is
valid to git), keeps its mode, and replaces it atomically; only a missing file reads as empty,
and any other read error leaves the file alone (before, review 12 #1, a file that was not UTF-8
read as empty and lost every user rule when the engine opened). Git never runs a `*.sample` hook, and a
real hook is captured and restored like any `.git/` file. Nothing in the worktree or the
harness home is removed on a fresh executor: the disk is empty before the head is laid down
(`tests/fresh_boot_removals.rs` holds it: `removed` is exactly the template files no capture
holds, and the worktree and harness home come back whole).
Content and dir packs are fetched up front, eight GETs in flight (`PACK_GETS_IN_FLIGHT`), into
the pack cache (`.sealantd/capture/cache/`), and a pack already there is not fetched again.
`tests/delta.rs` measures it: a head applied over a
materialized base wrote 9 files / 213 KB where a fresh materialize writes 427 files / 1.7 MB,
the two trees compare identical (bytes, modes, mtimes, links — tracked files' too, through the
worktree metadata overlay), and the head over itself writes and changes nothing. This is what lets a standby executor pre-materialize the project base and apply the
claimed worktree's head over it (`capture.replan`).

**A reused file keeps no link the capture does not hold.** A skipped file keeps its inode, and
with it every other name that inode has on this disk: a standby's setup (`pnpm install
--package-import-method=hardlink` of a `file:` package) links a tracked file into
`node_modules`, and a head whose source replaced the tracked file with its own copy since, or
split two tracked aliases, has the same bytes, so nothing is written and the old link stayed
(review 15 #2). An edit to the restored tracked file then reached the installed copy, and
setting the tracked file's mtime moved the copy's. A whole restore (`MaterializeClass::All`)
now builds the inodes the capture holds (`worktree_meta::DesiredInodes`): every restored
regular file — each tracked path, each file of the workspace and bulk classes — in one group
with the names the overlay's `hardlinks`, `shared` and `cross_links` and each class's own
hardlink groups join it to, every other name a group of its own. Before any link is made or any
mtime set, an inode holding names of more than one group is split: the group with the most
names on it keeps the inode, every other group's names move to a copy (same bytes, mode and
mtime; the directory keeps its mtime) and get their class's mode and mtime back. Only
multiply-linked files are looked at and only mixed ones rewritten, so the delta stays a delta;
a name outside the restore (pnpm's store) is no group's and stays where it is. A sealed final
capture restored whole checks both directions once every link is made: each group is one inode
per filesystem (`MetaError::LinkUnfulfilled`), and no inode holds names of two groups
(`MetaError::ForeignLink`). `tests/review15_delta_links.rs` holds it with pnpm's layout by hand
and, when `node` and `pnpm` are on `PATH`, a real install.

**A staging file is the restore's own.** A file is written, and a split name copied, into a
fresh name beside it (`.<name>.capture-tmp-<pid>-<n>`, `.<name>.capture-apart-<pid>-<n>`)
created with `O_EXCL` (`longpath::create_temp`), the counter moving on past any name already
there, and only that file is removed on a failure. The fixed names these were before consumed a
captured user file of the same name: the split's copy truncated `.b.capture-apart` and renamed
it onto `b`, and writing `b` did the same to `.b.capture-tmp` (review 16 #2). A sealed final
capture restored whole also fails the materialize when any file a chunked class promised is not
a regular file once the restore is done.

The git side stages the same way. `GitRepo::exclude_locally` (every capture open and reopen),
`write_head`, `write_packed_refs` and `install_pack` (a restore) write into a fresh
`.<name>.capture-tmp-<pid>-<n>` beside the file they replace and rename it over, and a pack's
index is written by `git index-pack -o` into a fresh name of its own (no reverse index). Before
(review 17 #2), they went through the fixed names `.git/info/exclude.capture-tmp`,
`.git/HEAD.capture-tmp`, `.git/packed-refs.capture-tmp` and
`.git/objects/pack/tmp-capture-<sha>.{pack,idx,rev}`: opening capture truncated a user file at
the first and renamed it over `info/exclude`, at the first open and again when a restarted
executor reopened a disk whose sealed capture held the file, and the next final flush sealed the
disk without it. `tests/review17_git_staging.rs` holds the open and the reopen.

**The next capture is incremental too.** A restored executor learns where the head's chunks are:
at open (and at a re-plan) the engine maps the chunks of every workspace and bulk pack the
registered head names that the materializer left in the pack cache (and, writing dir packs, the
dir objects of its dir packs), and keeps the chunk locations of earlier epochs that point into
packs the head names. The materialized files' stat is in the class indexes already, so the next
capture reads and packs only what changed and names the head's packs for the rest, across
epochs, on its chain. Before, a new epoch forgot every earlier epoch's chunk locations: the
first bulk capture after a resume read and uploaded the whole dependency tree again (Docker end
to end: 119,414 files and 1.4 GB for one new 300 MB file; `tests/resume_incremental.rs`: 300
files read and packed again, now 0, and a new file costs one read).

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
  Relinking (remove the name, link it) moves its directory's mtime, and that directory's class
  set it already — `node_modules` itself, a pnpm `file:` package's directories (the Docker end
  to end found 31 wrong): the directory gets back the mtime it had before the relink.
- **Hardlinks between untracked names of two classes.** An inode no tracked file names, named
  by the workspace class (an ignored file, `tree/…`) and by the bulk class (a file under
  `node_modules/`), is recorded in the document's `cross_links`: every name the two classes carry
  of it, found from this snap's workspace listing (a file whose link count exceeds the names the
  workspace class holds) and the bulk class's index (each name checked on disk). Each class
  still links its own names among themselves; a restore then links every group member to the
  group's first member under the rule a `shared` name follows (only a name on disk holding
  exactly the first member's bytes), gives relinked directories their mtimes back, and restates
  every member in its class's index (a link moves the inode's ctime), so a head over itself
  writes nothing. Found by review 2 (2026-09-28, #10): `ignored/x` hardlinked to
  `node_modules/pkg/x` came back as two files after a complete final flush. A small snap that
  finds such a file depends on the bulk index, so a final flush whose bulk snap staged a capture
  snaps the small class again, as it does for a tracked file's shared names.
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
- **The `.git` and harness roots** (review 2026-09-28, seventh pass, #2). The workspace class's
  root object names `.git`, `tree` and `harness` with their modes and mtimes, but the materialize
  restored only what is under them: both came back `0777` under the umask with the time of the
  restore. `.git`'s and the harness home's are now set last of all, after the refs, the index,
  every class, `info/exclude` and the overlay's relinks (`tree`, the worktree root, is the
  overlay's). `tests/restore_metadata.rs` compares `.git`'s own mode and mtime with the rest.
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
  `packed-refs`. A name that is not a plain `refs/…` name, or a target holding a control byte,
  fails the materialize.
- **A dangling symbolic ref stays.** `symrefs` is read off the loose ref files (the common
  directory's `refs/` and a linked worktree's own), not `git for-each-ref`, which resolves each
  one and leaves out a symbolic ref whose target does not exist (`git symbolic-ref
  refs/remotes/origin/HEAD refs/remotes/origin/missing`): it vanished from a complete final
  capture. It is restored as `ref: <target>` like any other, and is not in `refs` (it resolves to
  nothing). A symbolic ref to a symbolic ref keeps its own target. (`git fsck` reports a dangling
  symbolic ref as `invalid sha1 pointer`, on the source as on the restore, so such a capture's
  `fsck` reads `failed`.) A symbolic ref changing during the pack retries it, as a ref moving does.
- **A symbolic ref stored as a symlink stays one** (review 2026-09-28, seventh pass, #1). With
  `core.preferSymlinkRefs=true` git stores a symbolic ref, `HEAD` included, as a symlink whose
  link text is the target's name, and reads a symlink under the git directory whose text is a
  well-formed `refs/…` name as a symbolic ref (any other symlink it follows, and reads the file
  it reaches). The scan took regular files only, the workspace class leaves `refs/` and `HEAD`
  to the git section, and `for-each-ref` resolves such a ref (git 2.52) or skips it (2.55): a
  sealed restore brought `refs/heads/alias -> refs/heads/main` back as a direct ref and a
  dangling one not at all. `gitpack::symlinked_symref` reads git's rule; `symrefs` now holds every
  symlinked symbolic ref by its link text (dangling and chained ones, names that are not UTF-8),
  and `HEAD` is its link text. **How the ref was stored is kept too**: git reads a `ref:` file and
  a symlink alike, but they are not the same bytes, and `for-each-ref` of git 2.55 lists one and
  not the other. The workspace class carries each symlinked symbolic ref and a symlinked `HEAD` as
  the symlink it is — link text and mtime — beside its entry in the git section; the git class
  writes it as text first (`write_head` renames over a symlinked `HEAD`, never writing through it
  into the branch it names), and the workspace class puts the symlink back. A reader that knows
  only the git section reads the same refs, stored as text. Loose versus packed is still not
  kept: every direct ref is restored packed, as before.
- **Ref names are bytes.** A ref name, a symbolic target and `HEAD`'s target are read as bytes
  and kept as `tree::key_of` keys (see "Dir entries: `raw_name`, `raw_target`, `unread`"), and a
  restore writes the bytes each key stands for (`packed-refs` sorted by those bytes). Decoded
  lossily, `refs/heads/caf\xe8` and `refs/heads/caf\xe9` were both `refs/heads/caf\u{fffd}`: one
  overwrote the other in `refs`, its commit was no pack tip, and a complete final capture lost it.
- **A symlinked pseudo-ref or operation document is read through the link** (review 2026-09-28,
  eighth pass, #2). Git reads `FETCH_HEAD`, `MERGE_HEAD`, `ORIG_HEAD` and the files of
  `rebase-merge/`, `rebase-apply/` and `sequencer/` through a symlink (one whose text is a
  well-formed ref name is that symbolic ref, whose objects the refs carry). The collector of what
  they name (`GitRepo::operation_objects`) read regular files only: a `FETCH_HEAD` symlinked to
  `held/fetched` inside `.git` came back byte-exact, and the commit and unique file it named did
  not. It now reads a symlinked document through its link, as git does; one that cannot be read
  (a link to a directory or a fifo, permission denied, a loop) is unresolved, and a final snap
  over it fails (`snapshot-failed`) — what it names is unknown. A dangling one names nothing, as
  a missing one does. `tests/review8_fidelity.rs` restores the commits of a symlinked
  `FETCH_HEAD`, `MERGE_HEAD` and `sequencer/abort-safety`.
- **A symlink with more than one name makes a final flush incomplete** (review 2026-09-28, eighth
  pass, #3; decision 23). Linux lets a symlink inode have several names (`ln` of a symlink,
  `cp -al` over a tree holding one). Hardlink groups, `shared` and `cross_links` are regular files
  only, so such names came back as separate symlinks from a sealed capture. Until a group of
  symlink names is carried, a final snap that reads a symlink whose link count is above one — in
  the worktree tree (`worktree_meta::Captured::linked_symlinks`), the workspace class or the bulk
  class — fails naming it (`snapshot-failed`, no seal); an automatic snap carries each name as its
  own symlink and warns.
- **A SHA-256 repository** (review 2026-09-28, eighth pass, #10). The materializer made a SHA-1
  repository, installed the SHA-256 pack into it and failed `read-tree` (`wrong index v2 file
  size`) before the workspace class brought `.git/config`'s `objectformat` back. The git section
  now names a format that is not SHA-1 (`object_format`, below), and the restore runs `git init
  --object-format=<format>` (`GitRepo::init_with_format`) before any pack goes in; a repository
  already there must be of that format. A section without it is SHA-1, restored with an explicit
  `--object-format=sha1` whatever `init.defaultObjectFormat` says. `tests/review8_fidelity.rs`
  round-trips a SHA-1 and a SHA-256 repository (committed, modified and untracked work, `fsck`).

`tests/restore_metadata.rs` writes a worktree with all of it (modes, ns mtimes of files,
directories, symlinks and the root, empty directories, a hardlink pair, names that are not UTF-8,
loose and packed refs, a symbolic ref, an annotated tag, a stash), captures it, materializes it fresh and compares everything; drifts the
restored disk (extra loose and packed refs, `HEAD` moved, modes and mtimes off, a broken hardlink,
a stray empty directory) and materializes the head over it; changes metadata alone and checks it
is captured and restored by a delta and a fresh materialize; links a tracked file to an ignored
and a bulk name and checks all three come back as one inode, and apart but byte-exact when the
bulk section is older. `tests/delta.rs` compares the mtimes of the whole working tree.

`tests/restore_metadata.rs` also final-flushes an ignored file hardlinked into `node_modules` and
an inode with two ignored names and one bulk name (plus a bulk-only pair across `node_modules/`
and `dist/`), and checks one inode per group, every mtime, and a write through one name showing
through the other.

Not covered: a directory whose restored mode forbids the owner to write (a later delta that
writes into it fails, loudly).

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
- **A base only.** The plan's remotes seed a repository built from an empty chain or from a
  capture that carries no `.git/config` (Mend's capture 0), adding each one it lacks. A capture
  that carries `.git/config` holds a session's own configuration, and it is the repository's:
  nothing is added, changed or removed, so a remote the user removed stays removed on a fresh
  executor (review 2026-09-28, fourth pass, #8). A disk resumed as it is gets nothing either.
  `MaterializeReport::git_config` says which a materialize restored.
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
sysctl first and never fails boot. The bulk class is watched with no bulk directory yet (the
small class's watches see one appear): a bulk directory made after the watcher started (a
session's first `pnpm install` runs after boot) gets watches then, listed again until a listing
finds nothing new, within the budget; past it, or where a directory cannot be watched, the bulk
class polls from then on. Before, it polled for the executor's life, and every final flush after
a complete one walked the dependency tree again (`final_is_current` needs both classes watched).
`tests/cadence.rs` measures all of it against the real watcher.

A watch sees a name, and a hardlinked file has others (review 2026-09-28, sixth pass, #2): a
write through a bulk name of a tracked file dirtied only the bulk class, and one through a name
outside the workspace dirtied nothing, so the class holding the old bytes was never snapped
again. `aliases.rs` keeps every multi-link regular file each class's last snap read, by inode.
An event on one name dirties every class holding another and notes each name for its class's
next build; an inode with names in both classes, or with more links than names the snaps saw, is
stat'ed on its class's maximum interval (the `capture-aliases` thread), and one whose size,
mtime or ctime moved dirties every class holding a name (`CadenceSnapshot::aliases_moved`). A
stat taken within 2 s of the file's last change is not trusted to show the next one. Behind
both, a watched class with nothing pending is snapped on its reconcile interval
(`Cadence::reconcile`, 60 s; `bulk_reconcile`, 600 s; `Trigger::Reconcile`,
`CadenceSnapshot::reconcile_fired`): the snap reads the class whole and stages nothing when
nothing changed. `tests/raw_bytes_and_aliases.rs` holds a write through either kind of name to
twenty maximum intervals.

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
  2. every writer is terminated and awaited, admission closed throughout, in this order —
     the workspace's own Docker containers, then the processes, then the containers again
     (below): SFTP bridges are closed, a process group the
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
     VM's agent and its `sealantctl` are never touched. sealantd, its threads, kernel threads
     and zombies are left alone, and so are its own helpers: the pids sealantd spawned itself
     and has not reaped (the spawn gate, `sealant_process::spawn`) that stayed in its own
     process group — the capture engine's `git` — with their children still in that group. A
     process that joined sealantd's process group, or that sealantd only adopted, is swept.
     Nothing else is spared, the far end of a control connection included: in Docker, Core
     reaches the socket through `docker exec … socat - UNIX-CONNECT:…`, and that `socat` is
     swept with the rest (nothing tells a relay from a writer). The reply to the request that
     ended the executor may be lost with it ("connection closed"); the outcome is not:
     `capture.status` reads it, and a final flush asked again answers it at once without
     stopping anything twice. Core, on "connection closed" during a final flush, reads
     `capture.status` or asks the final flush again. A daemon that is not PID 1 of its namespace and did not become a child subreaper
     cannot see an orphan, so every final flush it runs is incomplete (`sweep-unavailable`,
     logged at boot). And every running container of the workspace's own Docker daemon is
     stopped (`POST /containers/{id}/stop?t=<grace>`, `crates/sealantd/src/docker.rs`) until
     the daemon reports none running: a container can bind-mount the worktree. The daemon is
     `SEALANT_WORKSPACE_DOCKER_HOST`, else a `DOCKER_HOST` Core reserves for the workspace's
     own daemon — `unix:///run/docker/docker.sock` (Docker in the MicroVM, the Kubernetes dind
     sidecar) or `tcp://docker:2375` (the Docker adapter's dind sidecar); any other
     `DOCKER_HOST` (a host daemon) is never touched. The containers stop first, with the
     grace, while the processes still run: a workspace process can be what carries a
     container's output into the worktree (`docker logs -f > file`), and stopped at the same
     time it was gone before the container printed its last lines. After the processes, the
     containers are checked again and any a process started on its way out is stopped. A
     container left running, or a daemon named and not reached, is `processes-remain`;
  3. the small class and, forced, the bulk class are snapped (`CadenceRunner::flush_final`),
     both as `final` snaps —
     whatever the bulk clocks say; a scheduled bulk build in progress yields to it at its next
     chunk boundary and the forced snap resumes its progress, re-reading only files whose stat
     key moved or whose last read was racy (see "What a snap reads"); a file or directory it
     cannot read fails the snap (`EngineError::unreadable()`), it never becomes a deletion;
  4. everything ships, bulk included (`Shipper::flush_final`);
  5. before the seal, a census (`CadenceRunner::set_census`; the daemon's is
     `Runtime::census_writers`): every descendant of the daemon's alive now (its own gated
     `git` spared) is killed, and the classes are snapped again, since it may have written —
     the seal waits for a round whose census finds none, three rounds at most, and a process
     found on the last is
     `Incomplete::ProcessesRemain` (`processes-remain`), no seal. None is expected: no git of
     the capture's runs a filter or a hook. But a filter driver whose name was not UTF-8 once
     ran all the same and left a writer behind that wrote after the seal (review 2026-09-28,
     sixth pass, #1).

  Once a final flush stopped every writer, nothing snaps on a schedule any more: its forced
  snaps are the last (a turn snap or another final flush still runs). A scheduled bulk build
  the forced one preempted does not resume after it — the Docker end to end saw
  `bulk_building` true for 0.6–11.4 s after `complete: true`. A capture staged or being built
  after the final one turns `complete` false (`pending`) until it has shipped.

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
- **A retained executor boots in recovery mode.** Core keeps an executor that ended without a
  complete final flush, and recovers it by starting it again on its own disk (Docker:
  `docker start` of the kept container). That boot must save what the disk holds and add
  nothing, so it is a recovery boot (`crates/sealantd/src/boot`, `BootConfig::recovery`): the
  environment says `SEALANT_RECOVERY=1` (an adapter that starts a new container or Pod over the
  kept disk), or the file `/.sealantd-recovery` exists (a kept Docker container restarts with
  the environment it was created with: Core writes the marker into the stopped container with
  `docker cp` before `docker start`; the root of the container's filesystem is outside every
  capture root). A recovery boot resumes the disk's own staging and never materializes over
  it: it boots only when its staging continues the chain head, or its materialize of the head
  completed (`index/materialized.json` names the head's worktree tree; every change since is on
  the disk, to be snapped), and otherwise refuses to boot and touches nothing. It runs no
  lifecycle step, no dotfiles and no harness, and closes admission from the start (no exec,
  session or SFTP bridge); the ship worker uploads what is staged, a scheduled snap captures
  what changed since the last one, and the final flush — asked over the control socket, or run
  on the daemon's own stop — snaps both classes, ships, seals the chain and answers `complete`.
  It exits 0 only after a complete final flush, else 75, and a recovery boot that cannot start
  (the channel refuses, the disk is not its own, the capture token is gone) exits 75 too:
  still unsaved work, never a clean exit. Capture-store workspaces only (any other source
  refuses the flag). The capture token must still be there: a boot reads it from
  `SEALANT_SECRET_ENV_FILE`, which Core removes once the executor is ready, so Core must stage
  it again (a token Mend still honours for the session) before it starts a retained executor.
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
`crates/sealantd/tests/final_sweep.rs` a `setsid`'d, double-forked writer and a writer that
joined sealantd's process group stopped before the last snap, their `SIGTERM` handlers' files
in the head;
`tests/flush_modes.rs` a preempted scheduled bulk build not resuming after the final flush;
`crates/sealantd/src/capture.rs` no scheduled snap after a final flush, and a bulk capture
being built after it reported incomplete;
`crates/sealantd/tests/final_sweep_control_peer.rs` the relay carrying a final flush over a
real control socket swept with a bystander in the same scope, and the final flush asked again
answering `complete` (and `capture.status` the same) without a second quiesce; `crates/sealantd/src/capture.rs` also the
containers of a fake Docker daemon stopped (and a stuck one, or no daemon, incomplete), stopped
before the process streaming their output into the worktree (its last line in the head) and a
container a process started on its way out stopped after the processes, a
daemon without a subreaper incomplete, and a flush past its deadline completing in the
background and answering `complete` when asked again without a second quiesce;
`crates/sealantd/src/boot/capture.rs` another platform's dependency tree carried through an
executor's captures and restored on its own platform byte for byte.

## What a snap reads (`index.rs`, `roots.rs`, `watch.rs`)

A capture holds what is on disk, and says so when it cannot.

- **Nothing is excluded by name but git's own transaction files.** Outside the daemon's paths
  and the harness credential files, every regular file, directory and symlink under a class root
  is captured whatever it is called: an ignored `Cargo.lock`, `tmp/pids/server.pid`, a SQLite
  `-shm` (SQLite rebuilds a stale one when the first connection opens the database), a `.pack`
  without an `.idx`. Inside a git directory (a `.git` component; the workspace class mounts the
  repository's git dir at `.git/`) the exclusions are an allow-list of the files git names for a
  transaction in progress, each where git writes it (`index::is_git_transient`; review
  2026-09-28, eleventh pass, #2, cross-repo decision 33): `index.lock` (and a partial commit's
  `next-index-<pid>.lock`), `HEAD.lock` and the other root refs' locks (`ORIG_HEAD.lock`,
  `*_HEAD.lock`, `AUTO_MERGE.lock`, `MERGE_RR.lock`, …), `config.lock`, `config.worktree.lock`,
  `packed-refs.lock`, `shallow.lock`, `gc.pid` and its lock, `gc.log.lock`, any `.lock` under
  `refs/`, `logs/`, `reftable/`, `rebase-merge/`, `rebase-apply/` or `sequencer/` (a ref name
  never ends in `.lock`), `info/refs.lock`, `info/sparse-checkout.lock`, and in the object store
  `maintenance.lock`, `schedule.lock`, `info/*.lock`, `info/commit-graphs/*.lock`,
  `pack/multi-pack-index.lock`, `pack/multi-pack-index.d/*.lock`, `tmp_*` and `incoming-*`
  anywhere under `objects/`, a repack's `pack/.tmp-*` and a `pack/*.pack` without its `.idx`;
  the same names in a linked worktree's `worktrees/<name>/` (its per-worktree ones) and a
  submodule's `modules/<name>/`. Each is git's half-written state, made real by a rename the next
  snap sees. Every other file is the user's and is captured, in every class: a hook project's
  `.git/hooks/Cargo.lock`, a config include called `.git/personal.lock` (before, every `*.lock`
  under a `.git` was dropped, and a sealed restore lost both). A final flush drops a transaction
  lock too: it runs after every writer was stopped, so a lock found then is stale — the git that
  took it is gone and nothing will rename it; its content is a write git never made real, and
  git's own recovery is to remove it. Captured, it would come back and make every later git
  command of its kind fail; refusing the flush over it would keep an executor a killed git left
  a lock on from ever completing. Sockets, fifos and devices are not file content.
- **Local git-lfs objects are captured.** `.git/lfs/` rides in the workspace class (restored to
  `<root>/.git/lfs/`), so an object never pushed survives a replacement. The watcher does not
  descend into it (its sharded object directories would spend the watch budget); git-lfs writes a
  local object while `git add` writes the index, a watched change, and the snap it triggers walks
  `lfs/`, as does every forced snap.
- **A root reached through a symlink is read through it** (review 2026-09-28, eighth pass, #1).
  The configured roots — the worktree, its git dir (`.git`, `.git/` of the workspace class), the
  harness home — are read as git and the harness read them: a root that is a symlink to a
  directory (`.git` moved beside the worktree and linked back, a harness home configured as a
  link) is walked through the link, its entry is the directory it names, and its link text is
  kept in `workspace.root_links` (below). Before, `Listing::mount` saw a symlink where a
  directory was expected and returned an empty listing: `.git`'s bookkeeping (`config`,
  `MERGE_MSG`) and the harness transcript were captured as nothing, and the final flush sealed. A
  root that exists and is not a directory (a file, a link to one, a loop, permission denied) is
  unreadable, and a final flush over it answers `unreadable`; a root that does not exist (or a
  dangling link) holds nothing. Credential files are left out through the link as without it.
  The watcher watches a symlinked `.git` as a root of its own, through the link.
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
- **A path of any length** (`longpath.rs`). The kernel refuses a path of `PATH_MAX` (4,096)
  bytes or more in one call, and the third Docker end to end had one: an untracked file 4,186
  bytes below the root (17 directories of 243-byte names). Its `lstat` failed with
  `ENAMETOOLONG`, which failed the worktree metadata overlay, which failed every snap for the
  rest of the session. Every filesystem call a snap or a restore makes now takes a path of any
  length: one that fits goes to `std::fs`; a longer one is resolved through `openat`, a run of
  whole components at a time, and the call is made relative to its parent (`fstatat` through an
  `O_PATH` descriptor, `readlinkat`, `mkdirat`, `unlinkat`, `renameat`, `linkat`, `symlinkat`,
  `fchmodat`, `utimensat`); `longpath::walk` replaces `walkdir`. Git runs in the worktree and
  passes each path whole to one call, so it cannot reach a file of `PATH_MAX` bytes or more
  (`git add` dies: `unable to stat`) nor open a directory one byte shorter (it warns — in a
  message its 4 KB buffer cuts — and drops it). Those paths
  (`GitRepo::beyond_reach`: the long files git lists, and under the directory the cut warning
  still names whole, every untracked directory too long to open) are excluded from the add and
  carried by the workspace class like a nested repository (`tree/<path>`), and restored from
  there; ignored and bulk paths were never git's. A restore writes a file under a short staging
  name (a digest of the name) when `.<name>.capture-tmp-<pid>-<n>` would pass `NAME_MAX`. A directory too long to name to
  `inotify_add_watch` (it takes a path) is opened a run of components at a time and watched as
  `/proc/self/fd/<fd>`, at start and when one appears later; its events are named by its own
  path again. Only a directory that cannot be watched that way either makes its class poll (it
  made the small class poll, and every final flush after a complete one snapped it again).
- **One path is one path.** Whatever error one path's metadata gives (not only `EACCES`), it is
  that path's: the overlay reports it unreadable and carries its previous entry (and, for a
  directory it cannot list, the directories the previous document held under it); a `final`
  snap fails `unreadable` naming it. A `git add` that still dies on one path (`fatal: unable to
  stat`) sets it aside for the chunked class and runs again. A path too long for git that no
  class carries (a filesystem whose listings give no entry types) is reported the same way,
  never dropped. And a snap that fails for any other reason is counted in `capture.status`
  (see "`snaps` on `capture.status`").

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

### `manifest_features` and `executor` on `plan.get`

`manifest_format` says how dir objects are stored, not what a manifest means. The request also
lists every manifest feature this build reads, validates and carries on
(`registrar::MANIFEST_FEATURES`, `PlanGetRequest::booting`):

```json
→ {…,"manifest_format":2,
   "manifest_features":["worktree_meta","symrefs","other_bulk","raw_names","final_seal",
                        "git_trees","object_format"]}
← {…,"manifest_format":2,"manifest_features":[…],"executor":"<executor id>"}
← 409 {"reason":"manifest-features","message":"…","missing":["final_seal"]}
```

Mend refuses a head holding a feature the list leaves out, before it claims the lease (409
`manifest-features`, naming them in `missing`): an executor that ignores one restores less than
was saved (modes, mtimes, empty directories, hardlinks, symbolic refs, names that are not UTF-8)
or drops it from the captures it writes next (another platform's dependency tree). A feature is
held when: `worktree_meta` — the answered workspace section has `worktree_meta`; `symrefs` — the
git section has a non-empty `symrefs`; `other_bulk` — the stored head has a non-empty
`other_bulk`, or its ready `bulk` was captured on another platform than the request names;
`raw_names` — a dir entry of the answered workspace or bulk section carries `raw_name` or
`raw_target`; `final_seal` — the head carries `final_seal`; `object_format` — the git section
names one (a repository that is not SHA-1). The daemon reads a 409
`manifest-features` as a protocol error naming the missing features and what it reads (never a
chain conflict, never retried). `InMemoryRegistrar` refuses the same way (raw names aside: it
does not walk dir objects; `registrar::missing_manifest_features`). A request without the list
reads none; an answer without it is an older registrar's.

**A store that reads less than the daemon writes never gets a complete final flush** (decision
12; review 2026-09-28, fourth pass, #7). The daemon writes every feature it reads; a store whose
answer leaves one out (`git_trees` above all: without it the trees ride `refs` as pseudo-refs,
there is no raw tree, and a restore checks the worktree out as git converts it and drops a user
ref of a pseudo-ref's name) would restore less than a capture holds. Its captures still stage
and ship, as crash protection, but a final flush over it answers `complete: false`,
`incomplete_reason: "store-fidelity"`, and seals nothing (`CaptureConfig::unread_features`,
`CaptureConfig::fidelity_gap`). The executor is kept until a registrar that reads them recovers
it. Nor is any user code admitted over such a store (decision 16; review 2026-09-28, fifth pass,
#5): every periodic capture over it is lossy too — a hard crash's pickup restored CRLF work
normalized and a user ref of a pseudo-ref's name gone, three successful rounds in — so sealantd
refuses the boot right after `plan.get`, before the materialize, and exits 78, and refuses a
standby's re-plan onto it (the repository README has the contract). Only a recovery boot, which
admits no writer, runs over it. `object_format` is the exception: only a repository that is not
SHA-1 needs it, so a store that leaves it out is no fidelity gap for a SHA-1 repository
(`CaptureConfig::reads_object_format`); a final snap of a SHA-256 repository over such a store
fails (`snapshot-failed`, naming `object_format`), and an automatic one names the format all the
same.

### `upload_answers` on `plan.get`

The request lists the `upload.urls` answer shapes this build reads beyond a URL
(`registrar::UPLOAD_ANSWERS`, `PlanGetRequest::booting`): today `present`, a key the bucket
already holds, taken as uploaded (cross-repo decision 20; review 2026-09-28, seventh pass, #7).

```json
→ {…,"manifest_format":2,"manifest_features":[…],"upload_answers":["present"]}
```

A registrar answers `present` only to an executor whose `plan.get` listed it, and binds what was
listed to the launch that sent it. To an executor that did not (the field absent: every daemon
before this one, including the binary on a retained disk a recovery boots), it mints a URL as
before, conditional (`If-None-Match: *`): the PUT meets the store's 412, which every executor
takes as already uploaded. An executor from before `present` failed on it (`no url for <key>`) on
every retry, and its staged capture could not finish.

The answer's `executor` is the executor the session token was issued for: what a completed final
flush's seal names (below). Absent from a registrar that does not say, and the daemon seals under
`SEALANT_WORKSPACE_ID` instead (`CaptureConfig::executor`; a re-plan that names one takes it).

### `launch` on `plan.get`

Cross-repo decision 11: the executor names the launch it is from its very first `plan.get`,
additively (`PlanGetRequest::launch`, absent when it does not know):

```json
→ {"worktree_id":null,"epoch":0,…,"launch":"<launch id>"}
← 409 {"reason":"launch-mismatch","message":"…"}
```

It is `SEALANT_CAPTURE_LAUNCH_ID` when the launcher sets it (the launch Mend minted and issued
the session token for), else the launch this disk last served — the one its staging was written
for, or its last completed materialize was planned as (`CaptureEngine::disk_launch`): a restart
or a recovery boot names the launch whose disk it is. The registrar refuses a `launch` that is
not its token's (409 `launch-mismatch`) and binds the lease to (session, launch), so an old
launch's executor never joins a newer launch's epoch. The daemon checks the other way too: a
plan whose `executor` is not the `SEALANT_CAPTURE_LAUNCH_ID` it was given refuses the boot before
anything is materialized. And a disk's staging continues the chain across an epoch change only
for the launch that staged it (`index/last.json` records it): another launch's staging, or one
that names no launch, is not resumed into the new epoch however exactly it continues the head
(`CaptureEngine::pickup`; review 2026-09-28, fourth pass, #11). `InMemoryRegistrar` refuses a
mismatched `launch` as Mend does and keeps every request (`plan_requests`).

### `final_seal` in a manifest

Cross-repo decision 1: "saved" is a store-side fact, never only an RPC reply. When a final flush
completes — every writer stopped (the runtime's quiesce found none left), both classes snapped
after that, everything staged registered — the runner stages one more capture over the newest
one, its sections unchanged, `kind: final`, `n` = head + 1, carrying a top-level

```json
"final_seal": {"complete": true, "epoch": 3, "executor": "<executor id>"}
```

and ships it (`CaptureEngine::seal_complete`, `CadenceRunner::flush_final_sealing`). `complete`
is reported only once that register is acknowledged and says the seal is `recorded` (`seal` on
`capture.register`, below); a register refused and rebuilt in its
place (which drops the seal) is followed by the seal staged again, at most three times
(`sealing` otherwise). The seal is staged under the predicate `complete` is answered by
(decision 15; review 2026-09-28, fifth pass, #2): the flush first settles the watcher — it writes
a fence file in a directory of its own under the staging directory, watched by the same inotify
instance as the roots, and waits until the watcher thread has handled its event, so every change
made before it is counted (`WatchHandle::settle`) — then checks that no change signal came since
before its first snap, no repair is still asked for and no bulk build is paused. A change since
means the captures are not the disk: every class is snapped again, at most three rounds, and a
disk still changing answers `changed` (`Incomplete::Changed`) with no seal. Nothing the capture
itself runs can be that change: no filter driver or hook of the user's runs in its git
(`gitpack::git_command`). A clean filter that wrote a file git had already indexed changed the
disk under the flush, which sealed the stale captures before its report said `changed`. Absent from every other capture, so a manifest without it encodes exactly
as before. A final flush asked again over a sealed chain stages nothing; a capture staged after
it (a turn boundary) carries no seal, so the chain is unsealed until the next final flush seals
it again. A flush whose quiesce could not stop every writer (`processes-remain`,
`sweep-unavailable`) seals nothing. Without an executor identity nothing is sealed (logged at
boot) and `complete` is the reply alone, as before. Mend's register records a seal only when it
is complete, names the epoch the capture registers under and the executor the token is scoped
to; `InMemoryRegistrar::with_executor` does the same (`seals()`).

### `seal` on `capture.register`

Cross-repo decision 22 (review 2026-09-28, eighth pass, #5): a registered sealing capture is not
a recorded seal. A registrar may register the capture and withhold its seal (it is still
verifying what the seal names, or write authority it issued over those objects is still
outstanding) or refuse it (another executor or epoch). The register's answer says which
(`registrar::RegisterResponse::seal`, `SealAnswer`, `SealState`):

```json
← {"head_n":7,"head_capture_id":"<id>","seal":{"state":"recorded"}}
← {"head_n":7,"head_capture_id":"<id>","seal":{"state":"withheld","reason":"verifying"}}
← {"head_n":7,"head_capture_id":"<id>","seal":{"state":"refused","reason":"executor"}}
```

`seal` is answered whenever the registered capture (`n`, `capture_id`) carries `final_seal` —
on a lost-ack answer too (the chain already at `n` with that id), which then says where the seal
stands now — and is absent otherwise. `reason` is a short code, for logs and the flush's report.
`recorded` means recorded and standing: the registrar's plans and stop attestations may name
it. A final flush is complete only on `recorded` (`Shipper::seal_standing`, after the sealing
loop of `CadenceRunner::flush_final_sealing`). On `withheld` the daemon sends the same register
again, backing off (`RetryPolicy` backoff, doubling: ≈ 11 s over six asks, `ship::SEAL_REASKS`),
never past the flush's deadline or the shutdown cutoff; still withheld, the flush answers
`sealing` with the reason, and so does `capture.status` (`final_sealed` is false). A final flush
asked again asks again, without a new snap or seal when the disk is as it was — a daemon that
restarted over a sealed chain asks too (`CaptureEngine::sealing_register`). `refused`, and an
answer with no `seal` (a registrar from before this: decision 9, fail closed), are `sealing`
at once. Only `recorded` outlives the final flush that heard it: a final flush over an unchanged
disk that an earlier one heard refused or withheld sends the sealing register again, at once —
one register per final flush for a registrar that keeps refusing — so a registrar that refused
while it could not read the objects, and has recovered, is heard (review 12 #4). `InMemoryRegistrar` answers as Mend does (`withhold_seals`, `without_seal_answers`
stand in for a registrar still verifying and one from before).

### `root_links` in a manifest

The workspace section names each of its roots that was a symlink to a directory when captured
(`.git`, `harness`, `tree` for the worktree itself), by root name, with its link text as a
`tree::key_of` key (review 2026-09-28, eighth pass, #1):

```json
"workspace": {…,"root_links":{".git":"/work/real-git","harness":"real-harness"}}
```

The class holds what the link named, read through it. The link's target is outside what was
captured (on another executor it names nothing, or someone else's directory), so a restore
writes the root as a directory holding those bytes and leaves the link to the configuration;
`root_links` records that it was one. Absent when no root was a link, so a section without one
encodes exactly as before. Informational: no reader needs it to restore.

### `object_format` in a manifest

The git section names the repository's object format when it is not `sha1` (`git rev-parse
--show-object-format`; `GitSection::object_format`, `manifest::OBJECT_FORMATS`):

```json
"git": {…,"object_format":"sha256"}
```

A restore initializes its repository with it before it installs a pack (above). Absent for SHA-1,
so a SHA-1 section encodes exactly as before. It is a manifest feature (`object_format`): a
registrar refuses a head holding one to an executor whose `plan.get` does not list it, and a
store that does not list it gets no complete final flush of a SHA-256 repository. A format this
build does not restore fails a final snap. Every object id the section holds (refs, trees,
`HEAD`) is then 64 hex digits: a reader that checks a tip's width takes the section's format,
never 40.

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
pending). `incomplete_reason` says why not: `not-final`, `in-progress` (a final flush is running,
from its first moment — before it stops the writers — to its answer; it read `not-final` for
the 38 s one ran), `processes-remain`, `snapshot-failed` (a final snap failed, or a class's last
snap did, whenever: `snaps`), `fenced`, `conflict`, `deadline`, `ship-failed`, `pending`
(staged, or a bulk capture being built, after the final flush), `sealing` (everything
registered, but not the capture that seals the completed flush: the flush returned at its
deadline before it could stage it — send the final flush again, which seals without a second
quiesce; or the sealing capture registered and the registrar withheld or refused its seal, or
did not say: `seal` on `capture.register`, above), `sweep-unavailable`, `unreadable`, `store-fidelity` (the store does not read every manifest
feature this build writes, below), `changed` (the disk changed after the final snaps, or since
the flush answered) or `internal`; absent when `complete`.

Once `complete` is said, nothing more is captured. The final flush ends the chain as the disk
is: when its bulk snap staged a capture and the small snap found tracked or ignored files with
names in the bulk class (a pnpm `file:` package hardlinked into `node_modules`: the overlay records those
links from the bulk index, empty until the first bulk snap), the small class is snapped again
inside the same flush; and when the newest capture is not a final one (the final small snap was
staged ahead of a scheduled bulk capture still uploading, and the final bulk snap found that
capture current), a final capture with its sections seals the chain (`seal_final`, its manifest
only). Before, the flush after the one that said `complete` registered those (8 KB and 19 KB,
`files_read=0`), and until then the head was of kind `auto` or lacked the links. A final flush whose small snap
failed takes no bulk snap: it is incomplete (`snapshot-failed`) whatever that snap does, and on
a kept executor asked again and again each one walked the dependency tree for 2.4 s. An I/O
error names what was done and where (`write /…/.sealantd/capture/index/last.tmp: No space left
on device (os error 28)`, not the bare `No space left on device (os error 28)`), in the flush's
error and in `snaps[].last_snap_error`. A final flush
asked again (the drain's, the SIGTERM handler's, the boot's on the harness's exit) snaps
nothing when the last one snapped every class without an error, snaps are no longer allowed
(the writers are stopped, admission closed) and the watcher — watching both classes, never
overflowed — delivered no change since before that flush's first snap
(`CadenceRunner::final_is_current`): it ships what is left and answers in milliseconds, and
`complete` holds throughout (each walked the bulk class again for 2.5–3 s, `bulk_building`
meanwhile). A class that polls, or a change the watcher saw, snaps again. After a flush that
returned at its deadline (`deadline`, `ship-failed`), the worker ships the rest and the status
turns `sealing` (with an executor identity; `complete` without one): send the final flush again,
which seals the chain and then says `complete`. An older daemon's report decodes with `complete: false`.

A suspend flush after a complete final one, over the disk it captured, is a status read: it
snaps nothing and answers the final flush's report (Mend's Stop sent two after a final flush,
and each staged a `suspend` capture of the same tree, so the head read `suspend`); the engine
also stages no suspend capture of an unchanged tree over a final capture. Anything staged after
the final capture all the same (a turn boundary) turns `complete` false (`pending`), and the
next final flush seals the chain with a final capture before it says `complete` again, though
it snaps nothing (`CadenceRunner::chain_sealed`).

```json
← {"pending":0,"pendingBulk":0,"pendingBytes":0,"complete":true}
← {"pending":3,"pendingBulk":1,"pendingBytes":2147,"fenced":true,"complete":false,
   "incompleteReason":"fenced"}
```

### `snaps` on `capture.status` / `capture.flush`

`repeated CaptureClassSnaps snaps = 26` of `CaptureStatusReport`, one per captured class:

```proto
message CaptureClassSnaps {
  CaptureClass class = 1;
  uint64 snaps_failed = 2;                         // since the daemon started
  optional string last_snap_error = 3;             // while the last snap failed
  optional uint64 snap_failing_since_unix_ms = 4;  // when the current run of failures began
}
```

A snap that fails for any reason, scheduled or forced, is counted and its error kept until one
succeeds (logged at error when the class starts failing, at info when it recovers). While any
class's last snap failed, `complete` is false with `snapshot-failed`. The third Docker end to end
had every snap failing for the rest of a session with `pending 0` and `unreadable 0` and nothing
to say so. Absent from an older daemon.

```json
← {"complete":false,"incompleteReason":"snapshot-failed","snaps":[{"class":"small",
   "snapsFailed":7,"lastSnapError":"…","snapFailingSinceUnixMs":1790533559474},
   {"class":"bulk","snapsFailed":0}]}
```

### `pending_bytes` on `capture.status` / `capture.flush`

`uint64` field 14 of `CaptureStatusReport`: bytes staged on the executor's disk that no upload
has taken yet, over every pending capture, each object counted once, plus — while a bulk build
is in progress (`bulk_building`, `bool` field 25) — the packs that build has staged so far,
which no capture lists until it ends. `0` from an older daemon. A caller that has to decide
whether a workspace can go reads `complete` after a final flush; a drain loop reads
`pending == 0 && !bulk_building && pending_bytes == 0` (the Docker end to end read
`pending 0 / pending_bulk 0` with 463 MB staged by a build in progress).

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
             {"path":"shared.txt","class":"workspace","member":"tree/copy.log"}],
   "cross_links":[[{"class":"workspace","member":"tree/ignored/x"},
                   {"class":"bulk","member":"node_modules/pkg/x"}]]}
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
  and `raw_member` carries an escaped member's bytes. `cross_links` (absent when empty; added
  2026-09-28 within format `1`, so an older reader ignores it and restores each name as its own
  class captured it, as before) lists inodes no tracked file names that the workspace and bulk
  classes both name: each group is two or more distinct `{class, member, raw_member?}` (as in
  `shared`, members plain relative and not empty), sorted, workspace names first; the first is
  the one the others link to. A link names only members the captures hold as they are
  (review 2026-09-28, fifth pass, #11): a bulk name is linked only while its stat on disk is the
  one the last bulk snap read (size, mtime, ctime, inode); one that changed or gained a name
  since is left out of the group and waits for a small snap after a bulk snap
  (`CaptureEngine::links_deferred`). A final flush takes that snap, and is `snapshot-failed`
  while a link is still left out.
- Applying it (sealantd's `worktree_meta::apply`, after the worktree tree is checked out and every
  other class restored): create each `dir` that is missing; every other path must exist with its
  kind; remove the empty directories in scope that no entry names; link each group's members to
  its first path; link each `shared` member that holds exactly the tracked file's bytes to it
  (leave it otherwise); link each `cross_links` member on disk that holds exactly the bytes of
  its group's first member on disk to it (leave it otherwise). A linked member takes every other
  name of its class's own hardlink group along (`worktree_meta::apply_over`, `RestoredGroups`):
  the bulk index holds one name per group, so `shared` and `cross_links` name only that one, and
  pnpm's peer-context copies of a local package (two bulk names of a tracked file's inode) came
  back split, one of them on an inode of its own (review 12 #2). Once every link is made, a
  strict apply checks that the names the document and the restored groups join are one inode
  per filesystem (`MetaError::LinkUnfulfilled` otherwise). Then set files' and symlinks' mode and mtime (a symlink's own, never
  followed), then directories' deepest first. A sealed final capture restored whole (every
  class, its bulk section ready) promised its links: the materialize applies it strictly
  (`worktree_meta::apply_strict`), and a `shared` or `cross_links` member that is missing, not a
  file, or holds other bytes fails it with `MetaError::LinkUnfulfilled`, neither file written
  over. One inode has one mode and one mtime: names the document joins — a hardlink group, two
  tracked files sharing one name of another class, a cross-class group reaching a tracked file —
  promised different ones fail a strict apply with `MetaError::InodeConflict` before anything is
  changed (review 2026-09-28, seventh pass, #10; `MetaDocument::inode_conflict`). The writer
  never emits one: each name is stat'ed on its own, so an inode that moved between two stats
  reads as two promises — a final snap fails (`snapshot-failed`, no seal), any other snap gives
  every name the first name's (`MetaDocument::settle_inodes`) and the next snap takes the change.
  A registrar can refuse the same document before it seals. A member whose class this restore does not place is passed over. A reader that only lists or reads a class's files (Mend's
  `listCaptureDir`, `statCaptureEntry`, `readCaptureFile`, `materialize` of the workspace or bulk
  class) is unaffected: the overlay describes the git class's working tree, not a chunked class.

### `symrefs` in a manifest

`sections.git.symrefs`: symbolic refs other than `HEAD`, name → the ref it points at. Each is
also in `refs`, by the sha it resolved to at capture, so a reader that knows only `refs` reads
what it always did. Absent when empty, so a manifest without one encodes exactly as before. A
symbolic ref whose target does not exist is here and not in `refs`. A symbolic ref the repository
stored as a symlink is here like any other (its link text is its target); the symlink itself
rides the workspace class (`.git/refs/…`, `.git/HEAD`), so a restore stores it as it was.

Every ref name in `refs` and `symrefs` (keys and targets) and a symbolic `head` is a
`tree::key_of` key of the name's bytes: the name itself when it is UTF-8 without an escape-range
character (every name in practice, so no existing manifest changes), otherwise each byte of an
invalid sequence as `U+10FF00 + byte`. A reader writes `tree::bytes_of(key)` into `packed-refs`,
the loose symbolic ref and `HEAD`. There is no `raw_name` beside a ref: a key with a character in
`U+10FF80..=U+10FFFF` is an escaped one. A reader that writes the key's UTF-8 as the name gets a
different, distinct name (never two refs merged), and the objects are in the packs either way.

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
conflict. Nothing new on the wire; the reading changed. A heartbeat's 404 (or 409) `lease-lost`
pauses the harness at once rather than after the lease TTL; a heartbeat that succeeds under the
same identity resumes it.

`plan.get` answers 409 `{"reason":"worktree-leased"}` while another launch holds the worktree's
lease: no epoch is given, and a `live_epoch` in it is the holder's, never one to adopt
(`RegistrarError::WorktreeLeased`). A boot waits (1 s, doubling to 30 s) and asks again, touching
nothing; a re-plan keeps the identity it has. `InMemoryRegistrar::refuse_plans_leased` stands in
for it.

### `platform` on `plan.get`

The request carries the executor's `<os>-<arch>-<libc>` (the same key the bulk class stamps on
its captures, `engine::default_platform`). `<libc>` is the workspace userland's, not the
daemon's build: `musl` when the musl dynamic loader (`/lib/ld-musl-<arch>.so.1`) is there or
`ldd --version` names musl, `gnu` otherwise on Linux, `system` on any other OS — the answer
Mend's probe (`uname -s; uname -m; ldd --version`) gives for the same workspace. The key used
to come from the build (`cfg!(target_env)`), and the release daemon is a static musl binary: it
said `linux-x86_64-musl` in every glibc workspace, so every resume took the head's dependency
tree for another platform's and installed it again (Docker end to end, 2026-09-27: 177 files
rewritten, 988 MB captured again). A bulk section an older daemon stamped `-musl` in a glibc
workspace is answered `"pending"` once more (one install), kept in `other_bulk` as every other
platform's section is, and the next bulk capture fills `bulk` under `-gnu`. A registrar answers the head's bulk section as
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

### `flush` on `upload.urls` and `capture.register`: a preserving flush, named

Preserving work already admitted is never refused for budget reasons (cross-repo decisions 30
and 35; review 2026-09-28, eleventh pass, carried tenth-review #6: a registrar exempted only
what a control plane's drain had marked, so a final flush Core's deadline or the daemon's own
shutdown asked for was metered at `upload.urls`, and a held dependency tree stayed unsaved).
Once this executor begins a final flush — whoever asked for it: a drain, a runtime deadline,
`SIGTERM`, a recovery boot — every `upload.urls` and `capture.register` it sends carries
`"flush":"final"`, to the end of the process: the executor is ending, and everything it ships
from then on (the final captures, a bulk capture the flush's deadline left uploading, a held
capture asked for again) is the work it ends with. `PreservingFlush` is the one handle the
shipper stamps its registers from and the URL minter its `upload.urls` from
(`Shipper::with_preserving(minter.preserving())`); `CaptureRuntime::begin_final` and
`CadenceRunner::flush_final_sealing` begin it. A register is stamped when it is sent, never when
it is staged, so a capture staged before the flush and shipped during it is marked too.

```json
→ {"worktree_id":"wt","epoch":3,"keys":["captures/wt/3/packs/<sha>"],
   "sizes":{"captures/wt/3/packs/<sha>":150000000},"flush":"final"}
→ {"worktree_id":"wt","epoch":3,"n":7,"parent":"…","capture_id":"…","manifest_key":"…",
   "manifest":{…},"flush":"final"}
```

A registrar that reads the field exempts the request from its byte and call quotas, bounded per
launch against abuse but never refusing a first final flush. The field is additive: absent before
a final flush begins and from an older executor; a registrar from before it decodes the request
as it always did — Mend's request schemas are `Schema.Struct`s, which drop an unknown property —
and meters it as any other request, which is what it did before (the capture stays held, the
flush says incomplete, nothing is dropped). `InMemoryRegistrar::flush_seen` records what each call
carried, and `exempting_final_flushes` models a registrar that reads it
(`tests/quota_refusals.rs`, `a_final_flush_names_itself_on_upload_urls_and_register`).

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

- §"Capture format", Keys: "a new epoch never skips an upload because a prior epoch holds the
  bytes" → a new epoch reuses chunk locations only in packs the registered head it continues
  names (packs from earlier epochs on its chain, which the ADR already lets a manifest
  reference); anything else an earlier epoch staged is still never trusted. A pack the store
  lost after all is refused at register and rebuilt (see "A refused register is fixed, never
  dropped").
- §"Capture format", bulk `platform`: `<libc>` is the workspace userland's, detected at run
  time, not the daemon build's.

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
