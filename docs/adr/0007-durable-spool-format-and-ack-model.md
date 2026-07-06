# ADR-0007: Durable spool format and acknowledgement model

## Status

Accepted, 2026-06-20.

## Context

sealantd records a factual evidence trail (process I/O, PTY lifecycle, filesystem mutations, network metadata) inside a Sealant workspace and delivers it over the length-prefixed JSON Unix-socket protocol to the TypeScript SDK. The telemetry pipeline (plan §15) ends with `durable local spool → delivery → acknowledgement → retry or acknowledged deletion`. The spool is the crash-recovery and at-least-once boundary between in-process event production and the delivery sink, and it lives in the `sealant-eventlog` crate (plan §7: "append-only spool, checksums, recovery, rotation").

Constraints that force a custom on-disk format rather than reusing an embedded store:

- The daemon ships as a single statically-linked musl linux/amd64 binary that must run unprivileged across the Fedora-41, Arch, and `nixos/nix` base images (integration brief §6, requirement 14). No external broker, no dynamic distro libraries, no assumption of a particular filesystem feature set.
- The pipeline assigns final `Sequence` values "at one deterministic point per execution" (plan §15, integration brief §"Final event sequence values"), so the spool is the natural place where that already-sequenced, already-validated, already-redacted record is made durable. The spool must not re-sequence.
- Every record carries a sealantd-minted `EventId` (non-empty string compatible with `workspaceEventSchema.eventId`, integration brief §2/§8) and an execution `Sequence`. The `EventId` is the idempotency key used by the SDK to drop duplicates from at-least-once resend (plan §15 "Event IDs and idempotent delivery keys", "Duplicate-safe resend").
- Nothing may grow without a configured limit (plan §6.1 "No queue, map, frame, payload, retry buffer, spool ... may grow without a configured limit"); config exposes "Spool disk limit and segment size" and "Artifact thresholds" (plan §6.1, §8.4).
- Large blobs (process output, diffs/patches, packet captures) must not be inlined; they go to content-addressed artifact storage referenced by events (plan §16 closing paragraph, §13 "Diffs and artifacts", integration brief §4 — `data: Schema.Unknown` envelope carries a reference, not the bytes).
- The plan enumerates mandatory failure tests the format must survive (plan §16 "Mandatory failure tests"): truncated final record, corrupt checksum, disk full / permission failure, crash between write and fsync, duplicate replay, sequence gap, oversized record, rotation during active writes.

## Decision

Implement an append-only, segmented binary spool in `sealant-eventlog` with the following record layout, length-prefixed and self-describing so a partial tail can be detected without parsing JSON:

```
magic            4 bytes   constant, identifies a sealantd spool record
format_version   u16 BE    record/format version (independent of the wire protocol version)
record_length    u32 BE    byte length of [event_id .. payload], enforced against max_record_size
                           BEFORE allocation (same pre-allocation discipline as the 4-byte
                           wire frame prefix, integration brief §"Wire protocol")
event_id         var       length-prefixed UTF-8 EventId (idempotency / dedup key)
execution_seq    u64 BE    the deterministically-assigned execution Sequence (never re-derived here)
timestamp        u64 BE    record append time, monotonic-with-walltime, milliseconds
payload          var       typed event payload, serde JSON body (the same serde structs that are
                           the single schema source for the wire protocol; large blobs replaced
                           by a content-addressed artifact reference)
crc32            u32 BE    CRC32 over [format_version .. payload]
```

Format details and behavior:

- **Single sequencing point.** The spool persists the `Sequence` it is handed; it never assigns or reorders. This keeps the spool consistent with the rest of the pipeline (plan §15) and makes a `sequence gap` a reportable observation, not a spool bug.
- **Append and flush with configurable fsync policy.** Writes are append-only to the active segment. fsync policy is config-driven (plan §16 "Configurable fsync policy", §8.4) with at least: `always` (fsync per record), `interval` (fsync on a time/byte threshold), and `os` (rely on OS writeback). The "crash between write and fsync" test is satisfied because a record is only treated as durably delivered after the configured fsync point; anything past the last fsync is treated as a truncated tail on replay (see recovery).
- **Segment rotation.** The active segment rotates when it reaches the configured segment size; segments are named by their first execution `Sequence` for ordered replay. Rotation is atomic with respect to active writes (open the next segment, then redirect appends) so the "rotation during active writes" test holds.
- **Disk-limit enforcement.** Total spool bytes are bounded by the configured disk limit (plan §6.1, §8.4). When acknowledged segments cannot free enough space and unacknowledged data would exceed the limit, sealantd does not silently overwrite: it emits an explicit drop/degradation event (plan §15 "Drop counters and degradation events") and an unrecoverable-loss report (below). "Disk full and permission failure" surfaces as a typed eventlog error, never a panic.
- **Replay on restart.** On startup, segments are replayed in `Sequence` order. Each record is validated by `magic`, `format_version`, `record_length` (≤ max), and `crc32` before its payload is handed back to the delivery stage. Replayed records are re-delivered, not re-sequenced.
- **Truncated final record recovery.** During replay the reader stops cleanly at the first record whose header is incomplete, whose `record_length` would read past EOF, or whose `crc32` fails *and it is the last record in the last segment*. That tail is treated as never-committed and truncated to the last intact record boundary. This is the expected outcome of a crash between write and fsync and of "truncated final record".
- **Corruption detection mid-stream.** A `crc32` mismatch, bad `magic`, or oversized `record_length` on a record that is *not* the final tail is corruption, not truncation. The corrupt record is skipped to the next valid `magic` boundary and an explicit corruption event is emitted (plan §15 lists corruption as Critical priority, "never silently discard"). Recoverable records on either side are still delivered.
- **At-least-once delivery with idempotent EventIds.** Delivery may resend after a crash or sink disconnect (plan §15 "Sink disconnect/reconnect handling", "Duplicate-safe resend"). The `EventId` is the dedup key; the SDK is responsible for collapsing duplicates. The "duplicate replay" test asserts a replayed record is delivered again with the same `EventId` so dedup is possible.
- **Acknowledged-segment deletion.** Delivery acknowledgements advance a durable acknowledged-`Sequence` watermark. A segment is deleted only once every record in it is at or below the acknowledged watermark (plan §16 "Acknowledged-segment deletion", §15 "Retry or acknowledged deletion"). Deletion frees disk for the limit check above.
- **Explicit unrecoverable-loss reporting.** When records are lost for any reason — corruption skip, disk-limit drop, permission failure, or a tail discarded beyond what truncation recovery can salvage — sealantd emits an explicit, Critical-priority loss event carrying the affected `Sequence` range and cause (plan §16 "Explicit reporting of unrecoverable loss", §15 Critical row "never silently discard"). The evidence trail states its own gaps rather than presenting a falsely complete history.
- **Large blobs → content-addressed artifacts.** Payloads exceeding the configured artifact threshold (process output, text patches over the diff size limit, binary content, packet captures) are written to content-addressed artifact storage and the spool record carries the reference instead of the bytes (plan §16, §13). This keeps record size bounded for the pre-allocation `record_length` check and keeps the spool small relative to the disk limit.

## Consequences

### Positive

- Crash recovery and at-least-once delivery are grounded in a self-describing format: `magic` + `record_length` + `crc32` make truncation-vs-corruption decidable per record, which is exactly what the plan §16 failure-test matrix demands.
- The format is independent of the wire protocol version (`format_version` is its own field), so the on-disk spool can evolve without forcing a protocol bump, and vice versa.
- Bounded by construction: `max_record_size`, segment size, and disk limit are all configured (plan §6.1), and oversized records are rejected before allocation, mirroring the wire-frame discipline.
- Idempotent `EventId` keys plus an acknowledged-`Sequence` watermark give duplicate-safe resend and deterministic segment garbage collection without coordinating with the sink beyond simple acks.
- No external dependency: pure append-only files satisfy the single-static-musl-binary, unprivileged, cross-distro constraint (integration brief §6).

### Negative

- At-least-once (not exactly-once) pushes deduplication onto the SDK; the SDK must key on `EventId`. Documented as a contract obligation, but it is real work outside the daemon.
- A custom binary format means custom recovery code and a custom test harness for all eight mandatory failure modes; there is no battle-tested third-party store doing this for us.
- CRC32 detects accidental corruption and truncation but is not cryptographic; it does not defend against deliberate tampering with the spool file. Tamper-evidence, if required, is a separate concern.
- The acknowledged-`Sequence` watermark assumes in-order ack progress; out-of-order acknowledgement would pin a segment until its lowest record is acked, slightly delaying disk reclamation under partial-delivery conditions.
- Artifact offloading adds a second store to recover and reconcile: a spool record can reference an artifact whose write did not survive the crash, which must be reported as unrecoverable loss for that event rather than silently delivered with a dangling reference.

## Alternatives considered

- **Embedded key-value/LSM store (sled, RocksDB, SQLite).** Rejected: contradicts the single statically-linked musl binary that must run unprivileged across Fedora/Arch/Nix (integration brief §6); adds compaction and dynamic-linking/file-format risk on the non-FHS `nixos/nix` image; and an LSM hides the precise truncation-vs-corruption tail semantics the plan §16 failure tests require us to control explicitly.
- **One file per event.** Rejected: unbounded inode/file growth violates "nothing grows without a configured limit" (plan §6.1), makes ordered replay and segment-granularity acknowledged deletion awkward, and multiplies fsync cost.
- **In-memory queue with no on-disk spool.** Rejected outright: the pipeline mandates a durable local spool for crash recovery and at-least-once delivery (plan §15, §16); Critical-priority events (control errors, process start/exit, corruption) must be spooled before delivery and never silently discarded (plan §15 priority table).
- **Inlining large blobs in spool records.** Rejected: breaks the bounded `record_length` pre-allocation check and the disk limit, and duplicates bytes that content-addressed artifact storage already deduplicates (plan §16, §13).
- **Per-record acknowledgement and per-record deletion.** Rejected in favor of an acknowledged-`Sequence` watermark with segment-granularity deletion: per-record deletion fragments append-only segments and defeats the cheap "delete a whole segment once its max Sequence is acked" reclamation path.
- **Stronger/cryptographic checksums (SHA-256, BLAKE3) per record.** Deferred: CRC32 is sufficient for accidental corruption and truncation detection at low CPU cost in the hot append path; content addressing of artifacts already uses a strong hash where integrity matters most. A cryptographic per-record digest can be added under a new `format_version` if tamper-evidence becomes a requirement.
