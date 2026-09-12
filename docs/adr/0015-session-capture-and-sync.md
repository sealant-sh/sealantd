# ADR-0015: Session capture and sync — executors are caches of the store

Status: proposed 2026-09-12. Cross-repo context: Mend `docs/DEPLOYMENT-STRATEGIES.md` (the
co-located store invariant this supersedes for remote deployments), Mend ADR to follow (session
lifecycle, leases, hosted `SessionRepository`), Sealant Core (`RuntimeAdapter` per platform,
launch material, session channel). Builds on ADR-0008 (the `sealant-fs` watcher and snapshot walk).

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
| nodejs/node (~40k files): worktree add | 872 s | 2.5 s |
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

## Decision

### The invariant

> Every session has exactly one authoritative work product: its copy in the Mend store. An executor
> is disposable compute that holds a local copy of that work product and the session's lease.
> Evidence, diffs, checkpoints and review comments are ordered against the record sequence at which
> the store was last brought up to date.

This replaces "Mend and the workspace see the same worktree", which was the co-located
implementation of the older invariant, for every remote deployment. Local mode keeps its shared
directory as the degenerate case in which the executor's copy and the store are the same directory.

### What the work product is

The whole workspace, not tracked files: the worktree including uncommitted edits and the full
`.git` state (index, stash, reflog), dependency trees such as `node_modules`, build outputs and
workspace-local temporary files, and the harness home (transcripts, agent state). Exclusions are an
explicit short list of executor state: sockets, pid files, the OS `/tmp`, the daemon's own runtime
directory. Nothing the agent could need after a restart is excluded.

### The sync engine lives in sealantd

sealantd gains a `sealant-capture` crate (growing out of `sealant-fs`) with two stages and two ports.

**Stage 1, snap.** Freeze a point-in-time view of the tree without blocking the harness. The
baseline engine is userspace and filesystem-agnostic: an index of the tree (path, size, mtime,
inode, content hash) kept current by the ADR-0008 watcher, with a full stat scan as the fallback.
A snap copies the bytes of every file changed since the previous snap into a local staging area
under its content hash, chunked by content for large files, and writes a manifest listing the whole
tree by hash. Unchanged files are not read, hashed or copied; cost is proportional to the change,
not the tree. Per file the copy is a true point-in-time; across files the snap is not atomic, and
the next snap corrects any tear. Where an executor's kernel offers a real snapshot facility, a
platform engine may produce the same manifest faster; the product never depends on one.

**Stage 2, ship.** A worker walks staged snaps oldest-first and sends them to the receiver over the
session channel: batched, compressed, resumable, retried, throttled so it never starves the harness.
It coalesces when behind (ten snaps during an install ship as one), while chain metadata records
which points existed. Shipped staging is dropped; unshipped snaps survive suspend and are the first
thing the suspend hook flushes.

**Ports.**

- `SnapEngine`: `snap(root, previous) -> StagedSnap`, `materialize(capture, root)`. Default: the
  userspace engine. Optional per-platform engines behind cargo features.
- `Receiver`: what the shipper talks to. The first receiver applies batches to a POSIX store on the
  Mend engine's own disk, so Mend's existing store, `SessionRepository`, checkpoints, diffs, blame,
  landing and review keep working unchanged. A content-addressed object store receiver (S3, R2,
  MinIO, a local directory) is the same port and a later, independent decision.

What is fixed and shared, never per platform: the capture manifest format, chain semantics (parent,
record sequence, kind: `auto | turn | checkpoint | suspend | final`), the lease rule, and the
lifecycle policy. A capture written on one platform must materialize on another.

### Lifecycle

1. **Start.** Mend creates the session and its first capture: the project base (a clone at the base
   ref, optionally with the user's image layer applied) plus the initial harness home. An executor
   claims the lease, materializes the latest capture onto local disk, and launches the harness. A
   hot executor may have pre-materialized the project base so the claim applies only the delta.
2. **Work.** The executor snaps after a short quiet period following any change, at every agent
   turn boundary, and on explicit checkpoint, then ships. Each capture carries the record sequence
   at that moment. Mend's checkpoint is a named capture. Alongside a capture the executor posts the
   change summary Mend reviews from, so the review page never needs a live tree.
3. **Suspend and resume.** Suspend forces a snap and a flush. Resume on the same executor is free; a
   replaced executor resumes through pickup.
4. **Death.** Loss is bounded by the snap cadence: seconds, not turns. The lease expires by
   heartbeat.
5. **Pickup.** Clients act on the session, never on an executor. If the lease holder is alive the
   client attaches to it; otherwise Mend starts a new executor anywhere, on any platform, which
   claims the lease, materializes the head capture, restores the harness home, resumes the agent
   from its transcript, and continues. Death, the platform's lifetime cap, suspension past its
   window, and moving a session between platforms are the same path.
6. **Lease.** One executor per session at a time. A stale executor that wakes finds its lease gone
   and must stop shipping; the receiver rejects batches that do not extend the chain head.
7. **Land.** Landing a change reads from a capture, never from a live executor.
8. **End.** Stopping takes a final capture and releases the executor. The work product outlives it
   until the session is deleted; shared content survives while another session references it.

### What the platform adapters own

Only what they own today: launching the executor and reaching its PTY (Sealant Core's
`RuntimeAdapter`), delivering session configuration and a short-lived, session-scoped credential
for the receiver through the secret env channel, and the terminal ingress. No adapter knows what a
snap is. A platform's own facility (a sandbox's bucket backup, a loop-mounted btrfs on a MicroVM's
ext4 disk) may serve as a `SnapEngine` or as a same-platform fast restart, never as the only copy of
the work product.

## Consequences

- Sessions outlive executors by construction; the 8-hour MicroVM cap, sandbox replacement and phone
  pickup after a dead executor stop being special cases.
- No network filesystem in any hot path. The remote storage requirement becomes "a disk Mend's
  engine can read" plus Postgres; the object-storage tier is optional and additive.
- Git, installs and builds run at local-disk speed on every executor; the network sees batched,
  pipelined transfer bounded by bandwidth rather than by round trips. The 14-minute NFS install is
  a 15-second local install plus a background transfer.
- The loss window on executor death equals the snap cadence. Cadence and retention are numbers to
  choose (open questions below), not architecture.
- Materializing a session onto a fresh executor is a bulk transfer proportional to unique bytes and
  file count: seconds for ordinary repositories, tens of seconds for a 100k-file tree, hideable with
  a hot pool that pre-materializes the project base.
- A snap is not atomic across files. Tools that write several files in sequence can be caught
  between them; every file individually is a true copy, and the next snap corrects the tear. Git
  and editors write per file and rename, so this does not show up in practice.
- Local disk on the executor holds unshipped staging; a burst of writes costs one heavy snap of
  seconds of CPU and staging space until shipped.
- The receiver is a new component on the Mend side, one per deployment, writing the store on the
  engine's disk. Durability of that disk is the platform's disk story until the object-storage
  receiver exists.
- Mend's engine changes are confined to the lease, executor replacement, and treating the store's
  copy as observed-at-sequence rather than live; the read paths stay as they are.

## Alternatives considered

- **Keep the shared filesystem and tune it.** NFS client caching (`actimeo`, `nocto`,
  `lookupcache=all`) trims warm status but cannot fix checkout, since file creation is a synchronous
  round trip per file; `async` exports trade durability for a partial gain. Rejected: the cost is
  structural to per-file network operations.
- **Other network filesystems.** FSx for Lustre needs a client kernel module the MicroVM cannot
  load; EFS is NFS with worse latency; EBS cannot attach to a MicroVM; S3-backed FUSE mounts lack
  the atomic rename and locking git requires. Rejected.
- **Git-only capture** (snapshot the worktree as commits, push checkpoints). Cheap and fits Mend's
  review model, but drops exactly what makes a resumed session feel resumed: `node_modules`, build
  outputs, uncommitted index and stash state, the harness home. Rejected as the primary mechanism;
  git checkpoints remain the history for tracked files.
- **Kernel snapshots as the mechanism** (ZFS or btrfs send/receive). The right semantics: atomic,
  incremental, instant clones for the hot pool. But out-of-tree or absent on the kernels we do not
  control, which are the targets this decision exists for. Kept as an optional `SnapEngine` where
  available, never a dependency.
- **Object store as the primary store from day one.** Removes the receiver's disk and scales
  without thought, but moves every engine read path (diff, blame, checkpoints, landing, harness
  harvest) onto captures and change summaries, which is most of the engine. Deferred: the
  `Receiver` port makes it a later swap that does not touch the executor side.
- **A plain live mirror** (rsync-style sync without a snap stage). Meets the outcomes; the snap
  stage adds coherent points, non-blocking shipping and coalescing at small cost, so it is kept as
  the internal structure rather than a separate system.
- **Build the sync engine outside sealantd** (a sidecar such as mutagen, kopia or rustic). Mature,
  but a second process with its own lifecycle, credentials and platform matrix; the watcher, spool
  and hooks already live in sealantd. Embedding a library for chunking or dedup remains open.

## Open questions

- Snap cadence (quiet-period length, turn boundaries) and retention (how many captures per session,
  base compaction).
- Whether local mode snaps from day one or keeps the shared directory only.
- Whether the change summary is computed by the executor at snap time or by Mend from two captures.
- The first receiver's placement on platforms without a POSIX disk on the control plane
  (Cloudflare Workers): a container with local disk that offloads to R2, or the object-store
  receiver first there.
- Credential minting: short-lived receiver tokens per session are the existing session-channel
  shape; scoping for a future object-store receiver is per-prefix STS or presigned URLs.
