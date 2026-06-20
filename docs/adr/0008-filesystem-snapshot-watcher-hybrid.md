# ADR-0008: Filesystem snapshot/watcher hybrid

## Status

Accepted, 2026-06-20.

## Context

sealantd must answer "which files were added, modified, renamed, deleted, or had metadata changes?" for a run (plan §3 evidence questions, integration brief §"What happened"). Filesystem telemetry lives in the `sealant-fs` crate (plan §7: "snapshots, hashing, watcher, coalescing, diffs") and feeds the same sequenced, spooled, delivered pipeline as every other event.

The core problem is that no single Linux mechanism gives a complete, correct file-change record:

- inotify is the only unprivileged live mechanism available (eBPF/ptrace/cgroup hooks need capabilities the blueprint→adapter path does not convey today — integration brief §6, plan §14.1 `privileged` mode), so we favor in-process instrumentation.
- inotify can drop events: its kernel queue overflows under load and the plan calls this out directly — "Inotify can overflow and does not provide perfect process attribution" (plan §5), "Do not claim reliable per-process attribution from inotify alone" (plan §13).
- A pure snapshot/diff misses intermediate states (a file created and deleted mid-run) and is expensive to run continuously.

The plan therefore prescribes a hybrid correctness strategy (plan §13): baseline snapshot, live event observation, final snapshot and diff, and overflow/uncertainty recovery through rescan. The normalized event vocabulary is fixed (plan §13): `file.added`, `file.modified`, `file.deleted`, `file.renamed`, `file.metadataChanged`, `file.watchOverflow`, `file.snapshotCompleted`, `file.diffAvailable`. These serialize into the `{ eventId, sandboxId, attemptId?, type, occurredAt, message?, data }` envelope (integration brief §4) like every other sealantd event, with each event carrying its execution `Sequence` and a `captureMethod` of `inotify` or `snapshot` (plan §10 `captureMethod`).

Operational constraints that shape the watcher: blocking work (filesystem walks, hashing) must not run on async tasks ("use dedicated blocking tasks or threads", plan §6.1); everything is bounded ("process registry, or artifact store may grow without a configured limit", plan §6.1, with config exposing "Watch roots and ignore rules" §6.1 and "Filesystem include/ignore rules" §8.4); and large diffs/binary content go to content-addressed artifacts (plan §13 "Diffs and artifacts", same artifact store as ADR-0007).

## Decision

Implement filesystem telemetry in `sealant-fs` as a four-part hybrid, restricted to configured workspace roots:

1. **Baseline snapshot** at run start. Walk each configured workspace root on a dedicated blocking thread, recording per-entry snapshot metadata: path, file type, size, modification time, permissions, optional content hash, and symlink target (plan §13 "Snapshot metadata"). Hashing is optional and bounded by size policy so very large files are not hashed inline. Emit `file.snapshotCompleted` when the baseline finishes.

2. **Live inotify watch** over the same roots, added recursively. New directories created during the run get watches added; deleted directory trees have their watches removed (plan §13 "Add watches for new directories and handle deleted directory trees"). Live events normalize into `file.added` / `file.modified` / `file.deleted` / `file.metadataChanged` / `file.renamed`, with `captureMethod = inotify`. inotify reads run on a dedicated blocking task, not the async runtime.

3. **Final snapshot and diff** at run end. Re-walk the roots, diff against the baseline, and emit authoritative `file.*` events plus `file.diffAvailable`. The final diff is the source of truth for the run's net file changes; the live stream is the source of truth for *intermediate* and *ordering* information that a baseline/final diff cannot reconstruct. Where the live stream and the final diff disagree, the final snapshot wins for net state and the discrepancy is observable.

4. **Overflow-triggered rescan.** When inotify signals queue overflow (`IN_Q_OVERFLOW`) or the watcher otherwise cannot guarantee completeness, emit an explicit `file.watchOverflow` event and trigger a rescan of the affected root (plan §13 "Emit an explicit overflow event and trigger a rescan when the watcher cannot guarantee completeness"; plan §5). The rescan re-establishes a known-good snapshot baseline so subsequent diffs remain correct; events derived from a post-overflow rescan are marked as rescan-sourced rather than precisely time-ordered.

Required protections and qualifications:

- **Workspace-root restriction.** Observation is restricted to configured workspace roots (plan §13, §6.1 "Watch roots"; integration brief §4 "Workspace/repository scope"). Paths outside the roots are never snapshotted or watched.
- **Symlink-loop and path-escape protection.** The walker tracks visited (device, inode) pairs to break symlink loops and refuses to follow links that resolve outside the configured roots (plan §13 "Protect against symlink loops and path escape"; this is the same symlink-safe path discipline noted in the threat model, plan §"Use validated paths and symlink-safe operations"). Symlink targets are recorded as metadata, not traversed across the root boundary.
- **Editor temp-file coalescing.** Editor save patterns (write-temp → rename-over, e.g. `.swp`, `~`, `.tmp`, dotfile-then-rename) and repetitive `file.metadataChanged` noise are batched/coalesced so a single logical save does not emit a storm of low-value events (plan §13 "Batch/coalesce editor temp-file patterns"; plan §15 Low priority "First candidates for coalescing"). Coalescing happens before sequence assignment.
- **Ignore rules for generated trees.** Configured ignore rules apply to generated trees such as `node_modules` (plan §13 "Apply ignore rules to generated trees such as `node_modules`"; §8.4 "Filesystem include/ignore rules"). Ignored subtrees are neither watched nor diffed, which also keeps the inotify watch count bounded and reduces overflow pressure.
- **Rename detection: certain vs inferred.** When inotify pairs `IN_MOVED_FROM`/`IN_MOVED_TO` by cookie within the watched roots, `file.renamed` is marked **certain**. When a rename is reconstructed from a final-diff add/delete pair (matching size/hash/inode heuristics) or one side of the move left the watched roots, it is marked **inferred**. Each `file.renamed` event states which (plan §13 "State whether rename detection is certain or inferred").
- **No per-process attribution from inotify.** Filesystem events do not claim a producing `ProcessId` derived from inotify alone, because inotify provides no reliable attribution (plan §13, §5). Process correlation, if any, is left to the SDK and only from independently reliable signals — not asserted by `sealant-fs`.
- **Diffs and artifacts.** Text patches are generated only under configured type and size limits; larger patches and binary content become content-addressed artifacts referenced by the event (plan §13 "Diffs and artifacts"), reusing the same artifact store and threshold model as ADR-0007. Sensitive paths/content are redacted per policy before the event enters the pipeline.

## Consequences

### Positive

- Correctness does not depend on inotify being lossless: the baseline+final snapshot diff guarantees net file-change truth even when the live stream drops events, and `file.watchOverflow` + rescan makes any gap explicit rather than silent (plan §13, §5).
- The evidence trail is honest about uncertainty: rename detection is labeled certain vs inferred, and per-process attribution is never fabricated, matching the plan's truthfulness requirements (plan §13, §5).
- Unprivileged and single-binary friendly: inotify + userspace walks need no elevated capabilities, consistent with the static-musl unprivileged-across-distros constraint (integration brief §6) and avoiding the `privileged` eBPF/ptrace path (plan §14.1).
- Bounded by construction: ignore rules (`node_modules`), workspace-root restriction, and size-limited hashing/diffing keep watch counts, walk cost, and artifact volume within configured limits (plan §6.1), and reduce inotify overflow pressure.

### Negative

- Two full walks (baseline and final) plus rescans cost I/O and CPU proportional to workspace size; this is offloaded to blocking threads (plan §6.1) but is real load on large repositories.
- The live event stream is best-effort: under sustained overflow, fine-grained ordering and intermediate states for the affected root are lost and only recoverable as net state via rescan/final diff. The trail records this loss but cannot reconstruct what was dropped.
- Inferred renames and editor-temp coalescing are heuristic; pathological save patterns or hardlink/inode-reuse can mislabel a rename or merge distinct logical changes. The certain/inferred flag exposes this but does not eliminate it.
- No per-process attribution from this collector means questions like "which command touched this file" are not answerable from `sealant-fs` alone today; closing that gap requires the privileged path the adapter does not convey (integration brief §6).
- A baseline-to-final diff cannot see a file that was created and deleted within the run unless the live stream caught it; transient files are visible only with a healthy (non-overflowed) watch.

## Alternatives considered

- **Snapshot/diff only (no live watch).** Rejected: misses intermediate states and ordering, and cannot emit `file.added`/`file.modified` during the run; the plan explicitly requires live event observation as part of the hybrid (plan §13).
- **inotify only (no snapshots).** Rejected: inotify overflow and startup-race gaps mean it cannot guarantee a complete or correct net-change record, and the plan names overflow and attribution as known limitations (plan §5, §13). Without a baseline there is nothing to diff a rescan against.
- **fanotify / eBPF / ptrace for richer (and process-attributed) capture.** Rejected for now: these need elevated capabilities the blueprint→adapter path does not convey (integration brief §6), and the plan files them under the optional `privileged` network/observation tier (plan §14.1) to be degraded cleanly when unattachable. In-process inotify is the unprivileged baseline.
- **Following symlinks and walking outside workspace roots for completeness.** Rejected: violates the workspace-root restriction and path-escape protection (plan §13), risks symlink loops, and would capture evidence outside the run's declared scope.
- **Watching everything including `node_modules`/generated trees.** Rejected: unbounded watch counts and event volume violate the bounded-resource rule (plan §6.1) and dramatically increase inotify overflow probability; configured ignore rules exclude these trees (plan §13, §8.4).
- **Claiming per-process attribution by correlating inotify timing with the process registry.** Rejected: inotify gives no reliable PID, and timing correlation is unsound; the plan forbids claiming reliable per-process attribution from inotify alone (plan §13, §5).
