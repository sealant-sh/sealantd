# ADR-0002: Wire schema and framing

## Status

Accepted, 2026-06-20

## Context

sealantd speaks to a TypeScript SDK over a Unix domain socket (ADR-0004). The
plan requires explicit framing — "never assume one `read()` equals one message" —
and a "configurable maximum frame size before allocation" (plan §8.1). It also
mandates a single schema source: "Rust and TypeScript must derive from or
validate against a single schema source," and the initial developer mode "must
remain inspectable" (plan §8.2). Schema strategy must be recorded in an ADR
(plan §6 mandatory ADR subjects; plan §8.2).

No protocol, framing, or TS SDK exists yet (integration brief, status note). The
Rust stack to build it is already pinned in
`/Users/yiannis/Developer/oss/Selant/sealantd/Cargo.toml`: tokio-util's codec
module (length-delimited framing), serde / serde_json (bodies), and schemars
(JSON Schema emission). On the TS side, the monorepo's wire-facing contracts use
**Effect Schema**, not raw types: `Schema.NonEmptyTrimmedString` for IDs,
`Schema.Literal(...)` for enums, `Schema.optional(X)` for nullables,
`Schema.Struct` with camelCase fields (integration brief §5, from
`packages/api-contracts/src/core-api/sandboxes.ts`). The protocol must carry
arbitrary process and terminal bytes that are explicitly not UTF-8 (integration
brief §3 requires binary-safe stdin/stdout/stderr; plan §4.5 binary safety).

## Decision

**Framing.** Each protocol message is a length-prefixed frame: a **4-byte
big-endian unsigned length prefix** followed by a JSON body of exactly that many
bytes. A **configurable maximum frame size** is enforced **before allocation** —
the prefix is read first, checked against the cap, and a frame exceeding it is
rejected with the `frame-too-large` control error (plan §8.6 error set) before
any body buffer is reserved. This is implemented over tokio-util's
length-delimited codec (`Cargo.toml`). The same framing applies to the optional
stdio adapter (ADR-0004), where frames travel on stdout only.

**Schema source.** The **Rust serde structs in `crates/sealant-protocol` are the
single schema source** for commands, the event envelope, error codes, and IDs.
`schemars` derives a **JSON Schema** from those structs; that JSON Schema is the
artifact from which the TypeScript types in `packages/runtime-protocol` are
**generated and/or validated**. TS does not hand-author the wire shapes; it
either codegen's from, or checks itself against, the emitted schema. The TS types
follow the monorepo's Effect-Schema conventions (integration brief §5), and the
error code set is a closed `Schema.Literal` union mirroring the `Sandbox*Error`
tagged-error pattern (plan §8.6; integration brief §5).

**Binary payloads.** Arbitrary process / terminal bytes are never assumed to be
UTF-8. They travel inside JSON as **base64 plus an original `byteCount`** (the
decoded length). I/O telemetry events additionally carry the chunk metadata and
per-stream `streamOffset` defined in plan §8.4 and §12. `runtime-client`
provides binary payload helpers (plan §19 contract requirements) so consumers
decode base64 back to bytes without touching the wire encoding.

**Version field.** Every frame's envelope carries `schemaVersion` (plan §8.4),
negotiated on connect; an unrecognized version yields `unsupported-version`
(plan §8.6).

## Consequences

**Positive**

- Frames are human-inspectable during development (plan §8.2) — a JSON body is
  readable with standard tooling; no decoder is needed to debug a session.
- Allocation is bounded by the pre-checked length prefix, directly satisfying the
  oversized-frame threat (plan §18 "oversized protocol frames") and plan §8.1's
  allocate-after-check rule.
- One schema source (serde → schemars → TS) removes Rust/TS drift by
  construction and feeds the plan §19 requirement to generate Rust fixtures
  consumed by TS and vice versa.
- base64 + `byteCount` makes the protocol provably binary-safe for the
  gateway's bidirectional, non-line-buffered streams (integration brief §3).

**Negative**

- JSON + base64 inflates high-throughput I/O payloads (base64 is ~33% overhead
  plus JSON escaping) and costs encode/decode CPU on hot stdout/stderr paths.
- A 4-byte (32-bit) length prefix caps a single frame near 4 GiB; the
  configurable max-frame setting must sit well below that and large outputs must
  be chunked at the I/O layer (plan §12), not sent as one frame.
- schemars JSON Schema does not map 1:1 onto every Effect Schema construct, so
  the generation step needs a vetted mapping (e.g. base64 byte fields,
  newtype IDs) and a CI check that the emitted schema and TS types stay aligned.

## Alternatives considered

- **Protocol Buffers (or another binary codec) as the wire format.** Rejected for
  now. It loses the developer-mode inspectability plan §8.2 requires, adds a
  `.proto` build step and a second schema source competing with the serde
  structs, and front-loads tooling before the protocol has stabilized. The
  framing and envelope are deliberately codec-agnostic enough that protobuf can
  be **revisited for hot payloads** (bulk I/O chunks) later without changing the
  control-command surface — at which point its binary efficiency would address
  the JSON+base64 overhead noted above.
- **Newline-delimited JSON.** Rejected: it is unsafe for binary-bearing bodies
  and violates plan §8.1's "never assume one `read()` equals one message" by
  conflating record boundaries with content; length-prefixing is unambiguous.
