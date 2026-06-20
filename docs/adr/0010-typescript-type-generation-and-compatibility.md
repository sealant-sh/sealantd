# ADR-0010: TypeScript type generation and compatibility

## Status

Accepted, 2026-06-20.

## Context

The sealantd wire protocol is consumed by a TypeScript SDK
(`packages/runtime-protocol` + `packages/runtime-client`, plan §7; not yet
created per brief's status note). The Rust side is the single schema source:
serde structs in `sealant-protocol` with `schemars` deriving JSON Schema
(`Cargo.toml` carries serde/serde_json/schemars; plan §8.2 requires Rust and TS
to derive from or validate against one schema source). Plan §19 mandates: generate
or validate Rust and TS types from the same schema, expose exact error-code
unions, provide binary-payload helpers, support forward-compatible event
decoding, and generate Rust fixtures consumed by TS and TS fixtures consumed by
Rust.

The monorepo already fixes the TS conventions to mirror (brief §5, from
`packages/api-contracts/src/core-api/sandboxes.ts`): **Effect Schema**, not raw
types; `Schema.Literal(...)` for enums (never `Schema.String`);
`Schema.optional(X)` for nullable (never `Schema.Union(X, Schema.Null)`);
`Schema.NonEmptyTrimmedString` for IDs; `Schema.Struct` with camelCase fields;
export both `const xSchema` and `type X = typeof xSchema.Type`. Errors follow
the 8 `Sandbox*Error` classes (`sandboxes.ts:215-293`) using
`Schema.TaggedError` with HTTP status annotations. Packaging conventions (brief
§5, from `api-contracts/package.json` + `pnpm-workspace.yaml`): `"version":
"0.0.0"`, `"private": true`, `"type": "module"`, source `exports`
(`"." : "./src/index.ts"`, no build step), `effect`/`@effect/platform` via
`catalog:` (pinned effect `^3.21.0`, @effect/platform `^0.96.0`), internal deps
via `workspace:*` and `@sealant/` imports, `"lint": "oxlint ."`,
`"typecheck": "tsgo -p tsconfig.json --noEmit"`, vitest. Binary data crosses the
wire as base64 plus an original byte count, never assumed UTF-8 (brief intro,
plan §4.5). The ADR subject is named directly in plan §6.

## Decision

`@sealant/runtime-protocol` is **generated and validated from the Rust
`schemars` JSON Schema**, and mirrors `api-contracts` conventions exactly so it
reads as native to existing consumers.

**Schema source and generation.** `sealant-protocol` is the single source of
truth: serde structs derive `JsonSchema`; a build step emits the JSON Schema (a
`sealantctl`/codegen path), from which the TS Effect Schema definitions are
generated. The generated TS is checked into `packages/runtime-protocol/src`
(source-exported, no build step) and re-validated in CI against a freshly emitted
schema so drift fails the build. Rust serde remains the authority; TS never
hand-defines a wire type.

**Effect Schema mapping (mirroring brief §5):**

- IDs (`RuntimeId`, `ExecutionId`, `SessionId`, `ProcessId`, `RequestId`,
  `EventId`, `Sequence`, `StreamOffset` — plan §8.3) map to
  `Schema.NonEmptyTrimmedString`-based branded schemas, consistent with
  `sandboxEventSchema.eventId` (`sandboxes.ts:195`).
- Closed enums (capture modes, runtime states, event types) →
  `Schema.Literal(...)` unions, never `Schema.String`.
- Optional fields → `Schema.optional(X)`, never `Schema.Union(X, Schema.Null)`.
- Structs → `Schema.Struct` with camelCase fields; export `const xSchema` and
  `type X = typeof xSchema.Type`.
- Binary payloads → a `Schema.Struct({ base64: Schema.String, byteLength:
  Schema.Number })` helper (plan §4.5 / §19 binary-payload helpers), with
  encode/decode utilities in `runtime-client`; UTF-8 is never assumed.

**Error codes** are a single closed `Schema.Literal` code set, modeled as
`Schema.TaggedError` classes mirroring the `Sandbox*Error` pattern
(`sandboxes.ts:215-293`). The client deserializes any protocol error into a
typed member of that closed union; an unknown error code is itself a decode
error, not a silent pass-through (errors are closed, unlike events below).

**Forward-compatible event decoding.** Telemetry events use an open envelope
(plan §8.4, brief §4 §10): a known-`eventType` decodes to its typed variant; an
**unknown `eventType` passes through** as a generic event carrying its raw
`data` rather than failing. This lets an older client tolerate a newer daemon's
event types — required by plan §19 ("support forward-compatible event
decoding"). The version handshake on connect (REQ-PROTO-\*, brief §7) gates
breaking changes; additive event types do not bump the negotiated version.

**Shared fixtures.** Rust emits canonical fixtures (frames + events) that the TS
test suite decodes and validates; TS emits fixtures that Rust decodes and
validates (plan §19, both directions). These run in vitest (TS) and the Rust test
suite, tagged TST-TS-\* / TST-PROTO-\*, and are the contract regression net.

**Packaging.** Both `@sealant/runtime-protocol` and `@sealant/runtime-client`:
`"version": "0.0.0"`, `"private": true`, `"type": "module"`, `"exports": { ".":
"./src/index.ts" }` (source export, no build); `"effect": "catalog:"`,
`"@effect/platform": "catalog:"`; internal deps via `workspace:*` (e.g.
`@sealant/typescript` devDep) and `@sealant/` import style; `"lint": "oxlint
."`, `"typecheck": "tsgo -p tsconfig.json --noEmit"`. `runtime-client` provides
the plan §19 SDK surface (`health`, `getCapabilities`, `startExecution`, `exec`,
`openSession`, `writeStdin`, `resizePty`, `signalProcess`, `closeSession`,
`shutdown`, `events(): AsyncIterable<TelemetryEvent>`) over IPC — never FFI.

## Consequences

Positive:

- One schema source (Rust serde + schemars) eliminates hand-maintained TS wire
  types and the drift between them; CI fails on divergence (plan §8.2).
- Generated types are indistinguishable from existing `api-contracts` Effect
  Schema code, so SDK consumers face no new idioms (brief §5).
- Forward-compatible event decoding lets the daemon add event types without
  breaking deployed clients; only the version handshake gates real breaks.
- Bidirectional fixtures catch encode/decode mismatches in both languages before
  end-to-end tests, and exercise base64/byte-count binary safety explicitly.

Negative:

- A codegen + CI-validation step must be built and maintained; schema emission
  becomes a release-blocking gate.
- `schemars` JSON Schema does not map 1:1 to every Effect Schema idiom (branded
  IDs, tagged unions, optional-vs-null); the generator needs mapping rules and
  occasional annotations on the Rust side.
- Open event decoding means unknown events reach consumers as untyped `data`;
  the SDK and downstream code must handle the generic variant.
- Pinning `effect`/`@effect/platform` via `catalog:` couples the packages to the
  monorepo catalog version cadence.

## Alternatives considered

- **Hand-written TS types.** Rejected: guarantees drift from the Rust wire schema
  and violates plan §8.2's single-source requirement.
- **Raw `Schema.String` enums / `Schema.Union(X, Null)`.** Rejected: contradicts
  the established `api-contracts` conventions (brief §5); loses exact error/enum
  unions required by plan §19.
- **zod v4 (as used by `packages/sandboxes`/`validators`, brief §5).** Rejected:
  the protocol is consumed by an Effect-based API surface; mirroring
  `api-contracts` (Effect Schema) keeps one idiom at the wire boundary.
- **protobuf/gRPC instead of framed JSON.** Rejected here as a schema concern;
  the JSON-Schema-driven path keeps the developer mode inspectable (plan §8.2)
  and the framing choice is owned by ADR-0001.
- **Strict (closed) event decoding.** Rejected: a newer daemon emitting a new
  event type would break older clients, violating plan §19 forward
  compatibility.
- **FFI binding generation (napi-rs).** Rejected: plan §19 mandates IPC as the
  language boundary and bars Rust↔Node FFI as the runtime-control architecture.
