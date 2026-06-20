# ADR-0003: Identifiers, correlation, and sequencing

## Status

Accepted, 2026-06-20

## Context

sealantd must produce an evidence trail that correlates to the existing
control-plane without inventing identifiers that collide with, or
misrepresent, monorepo keys. The monorepo's correlation keys already exist
(integration brief §2):

- `sandboxId` — `text` PK, opaque/UUID-like; SSH carries it as `sbx-{id}` in the
  username (`apps/ssh-gateway/src/sandbox-target.ts`,
  `packages/db/src/schema/control-plane.ts` sandboxes table).
- `attemptId` / `runId` — **the same value**, the per-run correlation key;
  `sandbox_runtime_instances.run_id` is its PK 1:1
  (`packages/db/src/schema/sandbox-build-jobs.ts:23,67`;
  `control-plane.ts` sandboxAttempts).

There is **no process-, PTY-, session-, or event-ID format yet** (integration
brief §2). The only event-ID precedent is
`sandboxEventSchema.eventId: NonEmptyTrimmedString`
(`packages/api-contracts/src/core-api/sandboxes.ts:195`) — a bare non-empty
string with no prefix convention (`sbx_`/`run_` appear only in tests). The OS PID
is never a stable product identifier (plan §8.3; integration brief §2).

The plan requires Rust newtype identifiers (plan §8.3): `RuntimeId`,
`ExecutionId`, `SessionId`, `ProcessId`, `RequestId`, `EventId`, `Sequence`, and
precise sequence semantics — "event sequence represents the order observed or
enqueued by Sealant, not unknowable kernel causality," with I/O events also
carrying a monotonic per-stream `streamOffset` (plan §8.4).

## Decision

**Typed newtype identifiers.** `crates/sealant-protocol` defines newtypes for
`RuntimeId`, `ExecutionId`, `SessionId`, `ProcessId`, `RequestId`, `EventId`,
`Sequence`, and `StreamOffset`. They are distinct types in Rust (no accidental
substitution) and serialize as the wire shapes in the event envelope (plan §8.4).

**Identity binding.**

- `RuntimeId` identifies the **daemon instance** — one per sandbox+run. It is the
  `runtimeId` envelope field (plan §8.4).
- `ExecutionId` **carries the monorepo `runId` (== `attemptId`)**, the per-run
  correlation key. It is the `executionId` envelope field and is how every
  sealantd event joins back to `sandbox_runtime_instances.run_id`
  (`sandbox-build-jobs.ts:67`) and `sandbox_attempts`.
- `sandboxId` is **bound at config level** (plan §9 identity/execution config),
  not minted by sealantd — it is the daemon's static run scope (integration
  brief §1 binds the socket per sandbox; §2 requires every event carry
  `sandboxId`).
- **sealantd mints `SessionId`, `ProcessId`, and `EventId`.** No pre-existing
  format constrains them; the only precedent is the bare
  `NonEmptyTrimmedString` `eventId`, so the minted IDs are non-empty strings
  compatible with `sandboxEventSchema.eventId`
  (`api-contracts/.../sandboxes.ts:195`) and bind every event to
  `runId`(=`ExecutionId`) + `sandboxId` (integration brief §2, requirement 8).
- `RequestId` correlates a control request to its single acknowledgement and
  enables duplicate-request handling (plan §8.6).

**OS PID is not `ProcessId`.** `ProcessId` is a stable logical identifier minted
by sealantd. The OS PID, PGID, and pidfd-related metadata are recorded as
**separate fields** on the process record, never as the product-level identity
(plan §8.3; plan §10.4 pidfd/subreaper/PID 1; integration brief §2).

**Sequencing.** `Sequence` is the order **observed or enqueued by sealantd**, not
kernel causality (plan §8.4). Final `sequence` values are assigned at **one
deterministic point per runtime** — the single sequencing stage in
`crates/sealant-telemetry` (plan §7: "event bus, sequencing, priority, batching,
sinks") — so ordering is total and reproducible within a `RuntimeId` rather than
raced across producers. I/O events additionally carry a **monotonic
`StreamOffset` per stream** (plan §8.4, §12), giving per-stream byte/chunk
ordering independent of the global `sequence`.

## Consequences

**Positive**

- Every event self-describes its correlation: `runtimeId`, `executionId`
  (=`runId`/`attemptId`), `sandboxId`, plus minted `sessionId`/`processId`,
  so the trail joins cleanly onto `sandbox_runtime_instances` and the
  `sandboxEventSchema` envelope (integration brief §2, §4).
- A single deterministic sequencing point makes `sequence` total and
  reproducible per runtime, and makes the "order Sealant observed, not kernel
  causality" claim honest (plan §8.4; plan §18 warning against overclaiming).
- Newtypes prevent ID-substitution bugs at compile time and keep PID metadata
  from leaking into product identity.
- Per-stream `streamOffset` lets consumers reassemble exact byte order of
  stdout/stderr regardless of interleaving in the global sequence.

**Negative**

- The single sequencing stage is a serialization point; under event storms it
  must be the throughput-shaped path (batching/priority in
  `sealant-telemetry`, plan §15) or it becomes a bottleneck.
- `sequence` ordering is meaningful only within a `RuntimeId`; cross-runtime or
  cross-sandbox global ordering is not provided and consumers must not assume it.
- Carrying `runId` inside `ExecutionId` couples the protocol to the monorepo's
  opaque-`text` key format; if the control plane ever changes that format the
  newtype's validation must follow.

## Alternatives considered

- **Use the OS PID as `ProcessId`.** Rejected (plan §8.3): PIDs are reused, are
  unstable across the process lifecycle, and leak host detail; the stable logical
  ID with PID/PGID/pidfd as side metadata is required.
- **Assign `sequence` at each producer / sink.** Rejected: concurrent producers
  cannot agree on a total order, breaking idempotency and reproducibility; one
  deterministic assignment point per runtime is the only way the sequence
  semantics in plan §8.4 hold.
- **Reuse the monorepo `eventId` generator or adopt a `sbx_`/`run_` prefix
  convention.** Rejected: no such generator or schema-level prefix exists
  (integration brief §2 — prefixes appear only in tests); sealantd mints its own
  non-empty-string IDs compatible with the bare `NonEmptyTrimmedString` precedent.
