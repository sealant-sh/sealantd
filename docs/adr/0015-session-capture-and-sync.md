# ADR-0015: Session capture store — executors are caches of the store

Status: proposed 2026-09-12, amended 2026-09-12: mechanism replaced by the capture store (see Mend
decision 2026-09-12). Cross-repo context: Mend `docs/DEPLOYMENT-STRATEGIES.md` (the co-located
store invariant this supersedes for remote deployments), Mend `docs/adr/0002` (to follow: the
product half — per-worktree leases, hosted `SessionRepository`, the capture-store schema and the
session-channel routes; the counterpart of this document), Sealant Core (`RuntimeAdapter` per
platform, launch material, session channel). Builds on ADR-0008 (the `sealant-fs` watcher and
snapshot walk), ADR-0007 (the spool discipline the staging queue copies) and ADR-0003 (the
execution `Sequence` every capture is stamped with).

## Context

Mend's session model assumes the engine and the session's executor see the same POSIX filesystem:
the co-located store. On one machine that costs nothing and gives live review of the worktree,
checkpoints as commits, persistent harness homes and the hot pool for free. The moment the executor
is remote, the shared filesystem becomes a network filesystem, and every one we have deployed
charges per file operation: Longhorn RWX, CephFS, and this week FSx for OpenZFS over NFS from
Lambda MicroVMs. Git and package managers perform hundreds of thousands of file operations per
task, so the cost lands where users feel it. Measured 2026-09-12 against FSx OpenZFS (SINGLE_AZ_2,
160 MB/s, `nconnect=8`, 1 MiB rsize/wsize):

| Operation | NFS | local disk |
| --- | --- | --- |
| Mend monorepo: worktree add | 6.5 s | 0.2 s |
| Mend monorepo: `git status`, cold | 1.4 s | 0.08 s |
| Mend monorepo: `pnpm install` | 340–840 s | 12–15 s |
| nodejs/node (51,732 tracked files): worktree add | 872 s | 2.5 s |
| nodejs/node: `git status`, warm | 4.8 s | 0.07 s |

Interactive git on a medium repository stays usable; first touch of any tree and every operation on
a large tree do not. The cost is round trips per file, not throughput, so a faster file server does
not fix it. Beyond latency, the shared filesystem drags in semantics we do not control and keep
tripping over: uid mapping across writers, stale unix sockets on the share, a root-side `git gc`
poisoning the store, share-manager restarts, `secure` export defaults rejecting NAT'd clients.

The executors we want to run on are the ones whose kernels we do not control: Lambda MicroVMs
(no module loading, ext4 root, elevated capabilities but no ZFS/btrfs), Cloudflare Sandboxes, and
eventually laptops. A design that depends on a shared filesystem, or on a kernel snapshot facility,
excludes exactly those targets.

The first version of this ADR shipped captures to a POSIX receiver on the Mend engine's disk. That
fails the one platform that is a hard requirement: Cloudflare Containers have no durable disk on
the control plane and every request into a container crosses a Worker with a 100/200 MB body cap.
The amendment replaces the mechanism with one that works on every target; the invariant, the work
product and the lifecycle stand.

## Decision

### The invariant

> Every session has exactly one authoritative work product: its copy in the Mend store. An executor
> is disposable compute that holds a local copy of that work product and the session's lease.
> Evidence, diffs, checkpoints and review comments are ordered against the record sequence at which
> the store was last brought up to date.

This replaces "Mend and the workspace see the same worktree", which was the co-located
implementation of the older invariant, for every remote deployment. Local mode keeps its shared
directory as the degenerate case in which the executor's copy and the store are the same directory.
The key of the work product is the **worktree**: sessions are conversations against it, several
may be live at once, and all of them run inside the executor that holds the worktree's lease.

### What the work product is

The whole workspace, not tracked files: the worktree including uncommitted edits and the full
`.git` state (index, stash, reflog), dependency trees such as `node_modules`, build outputs and
workspace-local temporary files, and the harness home (transcripts, agent state). Exclusions are an
explicit short list of executor state: sockets, pid files, the OS `/tmp`, the daemon's own runtime
directory. Nothing the agent could need after a restart is excluded.

### The capture store

**Truth is object storage plus Postgres, never a POSIX receiver.** An S3-compatible bucket (S3,
R2, Garage, Ceph RGW; a local directory on one machine and in tests) holds immutable,
content-addressed captures. Postgres, owned by Mend, holds the only mutable state: the worktree
chain head, the lease with its fencing epoch, the pack lifecycle table and the project refs, each
advanced by a single-statement compare-and-swap. A capture is authoritative when, and only when,
its row is the chain head. Everything on an executor or on a Mend runner is a cache. MinIO is
archived (2026-04-25); the local S3 server is Garage.

**Lease and chain are keyed per worktree.** One executor per worktree. A joined or sibling session
(shell beside the agent, editor takeover) is another process inside the lease holder's executor; a
second executor for the same worktree is refused. The claim bumps the epoch and fences the chain in
the same statement. The executor carries its epoch on every session-channel call. A stale epoch is
answered with 409: the executor stops shipping and pauses its agent's process group with `SIGSTOP`
(`Signal::Stop` in `crates/sealant-protocol/src/command.rs`); it never kills. A heartbeat that
later succeeds with the same epoch resumes it with `SIGCONT`.

**Four content kinds, two pack kinds.** A workspace holds: (1) git objects; (2) `.git`
bookkeeping that is not objects — index, `HEAD`, refs, reflog, config, merge and rebase state; (3)
the harness home — transcripts, session databases, agent config; (4) dependencies and build
outputs. Kind 1 ships as **git packfiles**: Mend's API reads them natively, checkpoints are already
commits, and a 5–9 file change packs to 19–23 KB (measured). Kinds 2–4 ship as
**content-defined-chunk packs**: git stores whole blobs and a stored pack must be self-contained,
so one 6 KB append to a 9.5 MB transcript costs a 4,275,041-byte pack (measured), and importing
`node_modules` into git made 129,307 objects in 54 s (measured); chunking ships the changed tail
and dedups identical packages across sessions.

**Two classes.** `small` = the git pack for the tracked tree, the `.git` bookkeeping and the
harness home. `bulk` = dependencies and build outputs, keyed by `(os, arch, libc)`, coalesced and
registered independently; capturing it at all is a product decision (open question 1). The loss
window on executor death is bounded by the `small` class alone; a slow `bulk` upload never delays
a `small` capture.

### Capture format

Fixed and shared, never per platform. A capture written on one platform materializes on another.

**Keys.** Session-private objects live under an epoch prefix:
`captures/<worktree>/<epoch>/packs/<sha256>` (a git pack's index at `packs/<sha256>.idx`),
`captures/<worktree>/<epoch>/trees/<sha256>` (dir objects),
`captures/<worktree>/<epoch>/manifests/<capture-id>`. `<sha256>` is the lowercase hex digest of
the object's bytes; `<capture-id>` is the digest of the manifest's bytes. A new epoch never writes
under a prior prefix and never skips an upload because a prior epoch holds the bytes; a manifest
may reference packs from earlier epochs on its chain. Project-promoted content lives under
`projects/<project>/...` and is written only by Mend as a server-side copy (copy-on-promote);
executors never hold a URL there. No encryption in v1: the bucket's provider encryption at rest is
the whole story, and transcripts are in the bucket (open question 3).

**Manifest** (JSON, single PUT, written last). Fields:

```
worktree_id, n, parent (capture id | null), epoch, seq (execution Sequence at snap start),
kind: auto | turn | checkpoint | suspend | final, created_at (RFC 3339, executor clock),
sections: {
  git:       { packs: [key…], refs: { "<refname>": "<sha>" }, head: "<ref | sha>",
               fsck: verified | failed | unverified },
  workspace: { root: "<dir object key>", packs: [key…] },
  bulk:      { root: "<dir object key>", packs: [key…], platform: "<os>-<arch>-<libc>" } | "pending"
},
checkpoint?: { ordinal, sha, ref }
```

`packs` lists every pack the section needs to materialize, across epochs, so a capture is
materializable from its manifest alone. The manifest does not carry its own id.

**Dir objects.** A content-addressed listing of one directory, JSON, sorted by name: entries
`{ name, kind: file | symlink | dir | hardlink-group, mode, size, mtime, chunks: [sha256…] |
target | child: "<dir object key>", group? }`. A `hardlink-group` entry carries `target` = the
group's canonical path (its first member in path order) and no chunks, so pnpm stores materialize
as links. `group` names a file group read together (SQLite `db` + `-wal`). Symlinks record their
target and are never followed.

**CDC packs.** Restic-shaped container ≤ 64 MiB, one PUT, never multipart: a sequence of
zstd-compressed chunks followed by a trailing index (JSON array of
`{ hash, offset, length, size }` — compressed offset and length, uncompressed size), an 8-byte
little-endian index length and the magic `SLCP0001`. Chunk hash = sha256 of the uncompressed
bytes. Chunking is FastCDC v2020 with min 256 KiB / avg 1 MiB / max 4 MiB. Files smaller than the
minimum are one chunk. A chunk's pack is found through the pack indexes the manifest lists; dir
objects never encode `(pack, offset)`, so compaction on the Mend side rewrites one row per pack.

**Git packs.** Self-contained: `git pack-objects --revs` fed the closure of refs, `HEAD`, index,
stash and reflog tips, with the previous capture's tips as negatives; never `--thin`; the `.idx`
built with `git index-pack` and shipped beside it. Keyed by sha256 of the pack bytes. Readers
verify with `git index-pack --verify`.

**Write order.** packs → dir objects → manifest → register (the Postgres CAS over the session
channel). Every step before register is idempotent and unobservable. A manifest whose register
never ran is off-chain garbage that Mend sweeps with its epoch prefix after the grace period. A
register that reports the chain already at `n` with the same capture id is a lost ack, not a
conflict.

### Snap rules

- Per file a snap is a true point-in-time copy; across files it is not atomic. The next snap
  corrects a tear; `auto` captures are labelled partial in Mend for this reason.
- The git class is built from the closure of refs, `HEAD`, index, stash and reflog read **first**.
  After packing, refs are re-read; if anything moved, or `pack-objects` fails on a missing object
  (an agent's `git gc --prune=now` between the read and the pack), the engine re-reads and retries,
  bounded to three attempts, then ships with `git.fsck = unverified`. `git fsck
  --connectivity-only` runs on the packed closure before ship and its outcome is recorded per
  capture; pickup prefers the newest capture whose git section verifies.
- Excluded always: `*.lock` (including `index.lock`), `objects/tmp_*`, `objects/incoming-*`,
  `gc.pid`, SQLite `-shm`, sockets, pid files, the OS `/tmp`, the daemon runtime directory and its
  staging under `<workspace root>/.sealantd/`. Known harness credential files are on the exclusion
  list pending open question 2 (today: `.claude/.credentials.json`, `.codex/auth.json`; Core
  re-injects them at launch).
- SQLite `db` + `-wal` are one file group: read consecutively (`-wal` first), re-read as a group if
  either changed underneath, bounded to three attempts, then shipped marked torn in the entry.
- A `.pack` without its `.idx` in the workspace class is a mid-`index-pack` rename: skipped, never
  corruption.
- Append-only files (JSONL transcripts) may ship as the tail since the previous capture; the dir
  entry still lists the whole chunk list, so materialize does not know or care.

### Cadence and budgets

Small class: 2 s of quiet after any change, at most every 10 s while the tree stays dirty, at every
agent turn boundary, on explicit checkpoint, and on suspend, `SIGTERM` and terminate hooks. Bulk
class: coalesced on its own clock, never on the small clock. The shipper is throttled to ≤ 50% of
one core, enforced as a CPU-time duty cycle from `getrusage`, so it never starves the harness.
Staging is a hardlink of the source file when the stat check passes, a byte copy otherwise; staged
snaps survive suspend and are the first thing a flush ships.

The watcher runs under a watch budget. `sealant-fs` registers one non-recursive inotify watch per
non-ignored directory (`crates/sealant-fs/src/watcher.rs`), and its `DEFAULT_IGNORES`
(`crates/sealant-fs/src/snapshot.rs`: `.git`, `node_modules`, `target`, `.sealantd`, `.hg`,
`.svn`, `.cache`) are right for telemetry and wrong for the work product; capture roots use their
own policy. The executor image raises `fs.inotify.max_user_watches` to 524288 where the sysctl is
writable. On `IN_Q_OVERFLOW` (the `need_rescan` path that today emits `file.watchOverflow` and
re-snapshots) or where the sysctl cannot be raised, the engine drops to a periodic stat walk at the
cadence: 15 ms for 51k files, 120–130 ms for 131k (measured).

### Executor credentials

An executor holds exactly two things. (1) The session token, delivered through the secret env
channel as `SEALANT_CAPTURE_TOKEN` with the channel address in `SEALANT_CAPTURE_ENDPOINT`: scope =
its own session's channel routes; lifetime = the session; revoked at pickup and at replacement.
(2) Presigned per-key PUT and GET URLs: scope = one key under `captures/<worktree>/<epoch>/…`,
TTL 15 min, minted by `upload.urls` only after the lease predicate (`epoch = $epoch and
expires_at > now()`) passes, so a fenced executor obtains no new URL and its old ones lapse within
15 min. The channel enforces a byte quota (default 4× the project's compressed footprint) and a
request quota (default 2,000 URLs per hour) per session. The executor never holds bucket
credentials, Postgres credentials, a project-prefix URL or another epoch's prefix. Residual: within
its own live epoch and the URL TTL an executor can overwrite a key it wrote — self-harm, caught by
sha256 at read, and the reason pickup falls back to the newest verifying capture. Mend's compaction
grace period of 30 min (15 min TTL + 5 min materialize budget, rounded up) is derived from this
TTL; changing one changes the other.

### Transport

The session token and every presigned URL are bearer credentials, and the channel's answers decide
where a session's bytes go. The executor therefore dials both over HTTPS with a verified
certificate and does not fall back. A channel endpoint the policy does not dial refuses boot,
before the token leaves the process; an object URL it does not dial is refused when the registrar
answers it, before a byte is sent to it.

- Plain HTTP is dialled to the executor's own loopback, and otherwise only when the launcher sets
  `SEALANT_CAPTURE_ALLOW_PLAINTEXT=true`. That setting is a statement that the network between the
  executor and the channel is private (a VPC, a Docker network, a cluster network), made by
  whoever launches the executor. It covers the channel and the object URLs together, because an
  install with a plain-HTTP channel usually has a plain-HTTP object store beside it.
- `SEALANT_CAPTURE_CA_PEM` (inline) or `SEALANT_CAPTURE_CA_FILE` (a path in the executor image)
  names the roots the channel's certificate must chain to, **in place of** the bundled public
  roots: a channel behind a private CA, which nothing a public CA signs can stand in for.
  `SEALANT_CAPTURE_OBJECT_CA_PEM` / `SEALANT_CAPTURE_OBJECT_CA_FILE` do the same for object URLs
  (a private object store), so a private install is not pushed onto the plaintext exception. Each
  path trusts its own bundle, or the public roots when none is named.
- Certificate and host name verification cannot be turned off. The plaintext exception does not
  relax it.
- No redirect is followed, on the channel or on an object URL. A 3xx is an answer: a protocol
  error on the channel, an unexpected status on an object. A redirect would otherwise carry a
  request to a host or a scheme the policy never checked.
- A refusal names the host, never the path or query, since a presigned URL is a credential.
- Proxy variables in the daemon's environment (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are not
  honoured on either path. A plain-HTTP request allowed because it names loopback would otherwise
  be handed, token and all, to whatever the variable names.

Not covered: client certificates on the channel, a bundle that adds to the public roots instead of
replacing them, and reaching the channel or the object store through a mandatory egress proxy.
Each is later work if a deployment needs it.

### Ports and crate layout

`sealant-capture` replaces the `SnapEngine`/`Receiver` pair of the first version with four ports:

- `CaptureEngine`: index the roots, snap, pack, write the manifest.
  `snap(class, previous) -> StagedCapture`.
- `BlobSink`: `put(key, bytes)`, `get(key)`. Implementations `PresignedHttp` (URLs from the
  Registrar) and `LocalDir` (a directory; single machine and tests).
- `Registrar`: the session-channel calls, each carrying the epoch: `plan.get` (head manifest and
  GET URLs for materialize), `upload.urls` (PUT URLs for a key list), `capture.register` (the CAS;
  409 on a stale epoch or a wrong parent), `change.summary` (after a `checkpoint` register returns;
  accepted only against the chain head), `lease.heartbeat` (zero rows = lost, pause).
  `plan.get` may also name `sources`: gzipped tars the control plane wants beside the worktree
  (Mend's folders and reference repositories), each with an absolute path outside the worktree and
  the archive's sha256 as its content stamp. A capture-source workspace has no host mounts, so
  this is the only way that content reaches it; the boot lays it down and nothing there is ever
  captured back.
- `Materializer`: `materialize(manifest, class, root)` — packs into `.git/objects/pack`, refs into
  `packed-refs`, chunks reassembled into files, hardlink groups linked, mode and mtime restored.

Crate `crates/sealant-capture` (new): `index.rs` (grown from `crates/sealant-fs/src/snapshot.rs`
and `watcher.rs`, capture ignore policy), `chunk.rs` (`fastcdc` v2020), `pack.rs` (CDC packs),
`tree.rs` (dir objects, file groups, hardlink groups), `gitpack.rs` (closure ordering, `git
pack-objects --revs`, `index-pack`, `fsck --connectivity-only`), `manifest.rs`, `ship.rs`
(staging queue on the append → replay → ack discipline of `sealant_eventlog::Spool`
(`crates/sealant-eventlog/src/spool.rs`; segment rotation, healed tails, ack-based deletion, a disk
bound), presigned PUT with retry and resume, the CPU throttle; adds an HTTP client, the workspace
has none), `materialize.rs`, `sink.rs`.

Wiring in existing crates, all verified against today's tree:

- `crates/sealant-protocol/src/command.rs` `pub enum Command` (adjacently tagged `cmd`/`args`)
  gains `capture.now { kind }`, `capture.flush`, `capture.status`, `lease.epoch`, `capture.replan`
  (fetch the plan again and bring the workspace to it: a standby taking its worktree); results beside
  `ShutdownAccepted`; the protobuf mirror in `crates/sealant-protocol/proto/sealant.proto` and
  `convert.rs` per ADR-0012.
- `crates/sealantctl/src/main.rs` `enum Cmd` gains `capture flush` (and `capture replan`), which the platform hooks run
  (`/suspend`, `/terminate` on MicroVMs; a container `preStop`).
- `crates/sealantd/src/boot/config.rs` `WorkspaceSource` (`Clone | Mount | Standby`) gains
  `Capture(CaptureConfig)`, selected by `SEALANT_WORKSPACE_SOURCE=capture`; the boot match in
  `crates/sealantd/src/boot/mod.rs` gains the arm that calls `boot/capture.rs` (beside `git.rs` and
  `mount.rs`): fetch the plan, materialize, claim the lease, then continue to the harness.
- `crates/sealantd/src/app.rs` `spawn_signal_listener`: on `SIGTERM`/`SIGINT` run `capture.flush`
  (final small-class snap → ship → register, bounded by the shutdown grace period) before
  `ShutdownSignal::request_graceful`; a `runtime.gracefulShutdown` command does the same.

### Lifecycle

1. **Start.** Mend keeps the project's bare repo where it is today, or as a project base capture
   in the bucket where it has no disk. Session create writes capture 0 = base packs + empty
   workspace class. Launch passes `SEALANT_WORKSPACE_SOURCE=capture` and the channel endpoint and
   token through the secret env channel. sealantd materializes onto local disk, claims the worktree
   lease (epoch + 1, chain fenced in the same statement), then launches the harness. A hot executor
   pre-materialized the base and the arch-matched dependency cache; the claim applies the delta.
2. **Work.** Small-class snap on the cadence, at every turn boundary and on explicit checkpoint;
   bulk class independently. Each capture carries the execution sequence. A checkpoint is the
   in-workspace helper running Mend's four git commands followed by a `checkpoint` capture; the
   change summary is posted after that register returns and is accepted only against the chain
   head. Mend renders it as claimed, recomputes it to observed on a runner, and a missing summary
   is "compute it", never an error.
3. **Suspend and resume.** MicroVM `/suspend` → forced small-class snap and flush; Mend never
   suspends with unshipped bulk. `/resume` re-heartbeats; a stale epoch is refused and the harness
   is paused. Cloudflare has no suspend: `keepAlive` while live, `SIGTERM` flush on planned stops.
4. **Death.** Loss = the small-class cadence (2–12 s, estimate) plus any unregistered bulk
   (reproducible). The lease expires by heartbeat or is broken early by a platform probe.
5. **Pickup.** Clients act on the worktree, never on an executor. Lease alive → attach. Otherwise
   Mend confirms termination on the platform, claims (epoch + 1), launches anywhere, materializes
   the newest verifying capture, restores the harness home, resumes the agent by its provider
   session id. Death, the 8-hour MicroVM cap (replacement at ≈ 7 h 30), sandbox replacement and a
   platform move are one path; a move across architectures reinstalls dependencies (12–15 s,
   measured).
6. **Lease.** One executor per worktree; the epoch is the fencing token on every channel call;
   register and URL minting check it; a stale executor gets 409, stops shipping and pauses its
   agent. The lease fences the store, not the world: an agent's own `git push` with a
   connected-account token is not fenced by a Postgres row, which is why termination is confirmed
   before a claim and heartbeat loss pauses rather than kills.
7. **Land.** A Mend runner materializes the checkpoint's git class into its cache and pushes with
   Mend's server-side credentials, never from an executor.
8. **End.** `final` capture, lease released, executor destroyed. Retention keeps
   `checkpoint | suspend | final` for the session's life and thins `auto | turn` (24 h, then
   hourly, then checkpoints only); packs retire through Mend's `packs` table after the grace period;
   shared content survives while any capture on a chain references it. Liveness is computed from
   chain rows, never from manifests found in the bucket.

### What the platform adapters own

Only what they own today: launching the executor and reaching its PTY (Sealant Core's
`RuntimeAdapter`), delivering session configuration and the short-lived session credential through
the secret env channel, and the terminal ingress. No adapter knows what a capture is. Added by this
amendment: an adapter confirms termination of the old executor before Mend claims a replacement
(`TerminateMicrovm` then `GetMicrovm`; `destroy()`; pod delete); it wires the platform's stop
signal to a flush (`SIGTERM` in the container window, `/suspend` and `/terminate` hooks calling
`sealantctl capture flush`); and on Cloudflare planned stops call `stop()` (`SIGTERM`, up to
15 min) rather than `destroy()` (`SIGKILL`), which is reserved for confirmed-termination fencing. A
platform's own facility (a sandbox backup, a MicroVM snapshot) may serve as a same-platform fast
restart, never as the only copy of the work product.

## Consequences

Numbers are from the Mend decision of 2026-09-12: measured where it measured, estimates where it
estimated; transfer rate between bucket and executor is unmeasured on both clouds and every cold
figure is a multiple of it.

- Sessions outlive executors by construction; the 8-hour MicroVM cap, sandbox replacement and
  phone pickup after a dead executor are one path, not special cases.
- No network filesystem and no resident receiver anywhere. The remote storage requirement is an
  S3-compatible bucket plus Postgres; on one machine, a directory. The shared-filesystem incident
  class (uid split, root `gc` poisoning, stale sockets, `secure` exports) disappears because
  nothing is shared.
- Git, installs and builds run at local-disk speed on every executor. Per-change capture latency
  ≈ 2.5–3.5 s (2 s quiet + a stat delta + one small PUT + register; estimate); loss window on death
  ≈ 2–12 s of small-class state (estimate); bulk state is reproducible, not lost.
- Session start: hot pool ≈ 6–10 s on a MicroVM, 3–8 s in a sandbox; cold ≈ 25–40 s for a
  Mend-size workspace and 30–55 s for nodejs/node at 50–100 MB/s (estimate; ≈ 2 and 5 min at
  8 MB/s). Pickup after death: cold ≈ 35–65 s / 60–130 s, hot pool ≈ 10–15 s (estimate).
- A first `node_modules` capture costs 30–60 s of one core on a 2-vCPU executor (estimate from a
  2.65 s wall / 5.5 s CPU `tar | zstd` run); the small class is unaffected because the classes are
  independent.
- Storage: 100 Mend-size sessions ≈ 5 GB (base + one arch cache + ≈ 40 MB per session) against
  ≈ 314 GB of full worktrees; each additional architecture adds ≈ 815 MB per project (measured
  sizes, per-session figure an estimate).
- Mend's git operations run on a disposable runner with a pack cache: warm = today's numbers (diff
  3 ms Mend / 16–17 ms node), cold with the project base kept warm ≈ 1–3 s, cold without ≈ 40–60 s
  for node (1.54 GiB + fsck). On Cloudflare a container wake is added.
- A snap is not atomic across files; per file it is a true copy and the next snap corrects the
  tear. Git and editors write per file and rename, so this rarely shows; Mend labels `auto`
  captures partial.
- The executor's disk holds the tree, staging (hardlinks, ≈ 0 extra) and one pack set in flight:
  5–6 GB peak for a Mend-size session, so a Cloudflare `standard-3` (16 GB) fits and `standard-1`
  (8 GB) is marginal (estimate; image size unmeasured).
- Mend grows a compactor, a pack retirement job, per-session quotas and an observed pass for
  summaries; every "live worktree" read becomes a capture read. That work is Mend's and is the
  bulk of the 16–24 engineer-week estimate.
- The executor's own external credentials cannot be fenced by Mend. Stated, not hidden.

## Alternatives considered

- **Shared POSIX store plus a sync engine** (this ADR's first mechanism: a receiver applying
  batches to a POSIX store on the Mend engine's disk). Rejected: Cloudflare has no durable POSIX
  disk on the control plane, so the hard-requirement platform needs the capture store anyway and
  the receiver becomes a second system.
- **Stateful git server** (executors push to a per-project bare repository; Mend reads it in
  place). Rejected: on Cloudflare every push crosses a Worker with a 100/200 MB request body cap,
  so an 804 MiB dependency pack cannot arrive; and its captures are two pushes into two repos, not
  one atomic step.
- **Pure git-only capture** (snapshot the whole workspace as commits, push checkpoints).
  Rejected: git cannot chunk inside a file, so a 6 KB append to a 9.5 MB transcript costs a
  4,275,041-byte self-contained pack and a 60 MB codex rollout costs 13.4 MiB per push (measured);
  `node_modules` imported as 129,307 objects in 54 s. Git packs remain the format for kind 1.
- **Keep the shared filesystem and tune it.** NFS client caching trims warm status but cannot fix
  checkout, since file creation is a synchronous round trip per file; `async` exports trade
  durability for a partial gain. Rejected: the cost is structural.
- **Other network filesystems.** FSx for Lustre needs a client kernel module the MicroVM cannot
  load; EFS is NFS with worse latency; EBS cannot attach to a MicroVM; S3-backed FUSE mounts lack
  the atomic rename and locking git requires. Rejected.
- **Kernel snapshots as the mechanism** (ZFS or btrfs send/receive). The right semantics, but
  absent on the kernels we do not control, which are the targets this decision exists for.
  Rejected as a dependency; a platform may use one as a same-platform fast restart.
- **A plain live mirror** (rsync-style sync without a snap stage). Meets the outcomes; the snap
  stage adds coherent points, non-blocking shipping and coalescing at small cost, so it is kept as
  the internal structure rather than a separate system.
- **Build the sync engine outside sealantd** (mutagen, kopia, rustic as a sidecar). Mature, but a
  second process with its own lifecycle, credentials and platform matrix; the watcher, spool and
  hooks already live in sealantd. Rejected; `fastcdc` is embedded as a library.
- **Platform backup facilities** (Cloudflare `createBackup`/`restoreBackup`, `mountBucket`).
  Rejected for any hot path: the restore is a FUSE overlay lost on sleep, the backup is not
  consistent for partially written files, and `mountBucket` is s3fs.

## Open questions

1. **Dependencies as work product or reproducible.** Capture an agent-modified `node_modules` per
   session (bulk bytes, a cross-session supply chain if ever promoted), or treat dependencies as
   reproducible — Mend-controlled installs only, reinstall on architecture mismatch — which is
   cheaper and safer but changes what "resume" restores.
2. **Credential files in captures.** Keep `.claude/.credentials.json` and `.codex/auth.json` on
   the exclusion list and rely on Core's re-injection at launch (a pickup may prompt re-auth on
   some CLI versions), or capture them and accept a durable copy of every OAuth refresh token in
   the bucket.
3. **Transcript privacy and retention.** Provider encryption at rest or a Mend-held key; the
   retention window for `auto` captures that contain transcripts; whether hosted tenants share a
   bucket with prefix isolation or get one each.
4. **Local-mode shadow captures.** Run the engine in shadow mode on every laptop from day one
   (exercises the format, costs disk) or keep the bind-mounted worktree as the only local path.
5. **Cadence and retention budgets.** 2 s / 10 s and 24 h of `auto` captures cost ≈ $37–50 per
   month of request fees at 100 users (estimate); 5 s / 30 s halves that and doubles the loss
   window. Which loss window is the promise.

## Decisions made in this amendment

Choices this document makes that the Mend decision of 2026-09-12 left open. Each is a default a
reviewer may overturn without touching the rest.

1. Capture id = sha256 of the manifest bytes; the manifest does not carry its own id. Lost-ack
   retries therefore re-register the same id from identical bytes.
2. Dir objects are keyed under `captures/<worktree>/<epoch>/trees/<sha256>`; manifests under
   `manifests/<capture-id>` (the decision wrote `<n>.json`); a git pack's index at
   `packs/<sha256>.idx`.
3. A manifest lists every pack a section needs, across epochs, so a capture materializes from its
   manifest alone. Dir objects reference chunks by hash only; chunk → pack resolution uses the
   listed packs' trailing indexes.
4. CDC pack trailing index format: JSON entries `{ hash, offset, length, size }`, an 8-byte
   little-endian index length, magic `SLCP0001`; zstd per chunk; files under the minimum chunk
   size are one chunk.
5. Dir entry kinds `file | symlink | dir | hardlink-group`; a `hardlink-group` entry names the
   group's canonical path (first member in path order) and carries no chunks; a `group` field
   marks file groups (SQLite `db` + `-wal`), read `-wal` first, retried three times, then marked
   torn.
6. `git.fsck` values `verified | failed | unverified`; `fsck --connectivity-only` runs on the
   packed closure before ship; the manifest's `head` records `HEAD` as a ref name or a sha.
7. `objects/incoming-*` joins the exclusion list beside `*.lock`, `objects/tmp_*`, `gc.pid` and
   `-shm`.
8. Fence behaviour: pause with `SIGSTOP` on a 409 or once the 30 s lease TTL elapses without a
   successful heartbeat (heartbeat every 10 s); resume with `SIGCONT` if a later heartbeat succeeds
   with the same epoch; never kill.
9. Epoch travels as a field of every Registrar request, not in the token.
10. sealantd's names for the channel material: `SEALANT_CAPTURE_ENDPOINT` and secret
    `SEALANT_CAPTURE_TOKEN`; `SEALANT_WORKSPACE_SOURCE=capture` selects the source. Transport:
    `SEALANT_CAPTURE_ALLOW_PLAINTEXT`, `SEALANT_CAPTURE_CA_PEM` / `_FILE`,
    `SEALANT_CAPTURE_OBJECT_CA_PEM` / `_FILE` (§"Transport").
11. Staging lives at `<workspace root>/.sealantd/capture/` — the same filesystem as the tree, so
    hardlink staging works — and is excluded from captures; it uses the `Spool` discipline of
    ADR-0007 (append → replay → ack, segment rotation, disk bound), not its record format.
12. The shipper's ≤ 50% of one core is a CPU-time duty cycle from `getrusage`, not a cgroup.
13. Executor images raise `fs.inotify.max_user_watches` to 524288 where writable; the stat-walk
    fallback engages on `IN_Q_OVERFLOW` or an unraisable sysctl.
14. `SIGINT` flushes like `SIGTERM`; `runtime.gracefulShutdown` flushes too, bounded by the grace
    period.
15. The ADR title drops "and sync": the mechanism is a store, not a mirror.
