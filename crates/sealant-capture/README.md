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
directories of a `"pending"` bulk section. `tests/delta.rs` measures it: a head applied over a
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

## Wire additions

### `platform` on `plan.get`

The request carries the executor's `<os>-<arch>-<libc>` (the same key the bulk class stamps on
its captures, `engine::default_platform`). A registrar answers the head's bulk section as
`"pending"` when it was captured for another platform and omits its packs from `get_urls`:
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

Executor side, both answers are `RegistrarError::QuotaRefused` — terminal, never retried. The
shipper drops that queue entry with its staged bytes (and every queued capture that descends from
it: they name it as their parent), logs the capture's `n`, class and the numbers, and marks the
class `refused` in `capture.status`. A refused bulk class takes no further snap until the next
epoch or `capture.replan` (`Shipper::is_refused`, checked by the cadence's bulk loop); the small
class keeps snapping and shipping — its batches are small enough to fit what is left. The engine
reads the refusal at its next snap: the chain continues from the refused capture's parent, and
the chunk locations of packs that never went up — with the indexed files that reference them —
are forgotten, so the next capture packs those bytes again instead of naming a pack that does not
exist. Before this, a 409 was classified as a wrong parent and a 413 as a protocol error: both
stopped the pass, neither dropped the entry, and the ship worker re-ran the same call every 5 s
for good (observed on the cluster, 2026-09-14: a 775 MB bulk capture uploaded in full, then
`ship pass failed error=register n=4: … http 413` on every tick). `InMemoryRegistrar` takes a
byte quota (`with_byte_quota`) so both refusal points are tested (`tests/quota_refusals.rs`).

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

## Deviations from ADR-0015 pending amendment

- §"Capture format", CDC packs: "≤ 64 MiB, one PUT, never multipart" → packs stay ≤ 64 MiB but
  are uploaded as multipart at or above the shipper's threshold (default 16 MiB); git packs may
  exceed 64 MiB and are always multipart above it. The pack container is unchanged.
- §"Executor credentials": an executor also holds presigned per-part `UploadPart` URLs for its
  own keys, same scope and TTL as PUT URLs; Create and Complete stay with the registrar.
