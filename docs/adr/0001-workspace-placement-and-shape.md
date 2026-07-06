# ADR-0001: Workspace placement and shape

## Status

Accepted, 2026-06-20

## Context

sealantd is a new runtime daemon. As of this ADR nothing it must integrate with
exists yet: every crate under `/Users/yiannis/Developer/oss/Selant/sealantd/crates/*/src/lib.rs`
is a one-line doc-comment stub, `docs/runtime` and `docs/adr` are empty, and
`/Users/yiannis/Developer/oss/Selant/sealantd/packages` does not exist (integration
brief, status note). The Cargo workspace and its dependency stack are, however,
already real and pinned: `/Users/yiannis/Developer/oss/Selant/sealantd/Cargo.toml`
fixes edition 2024 on the stable toolchain with tokio + tokio-util codec, serde /
serde_json / schemars, thiserror, tracing, nix / rustix / libc, and clap.

The daemon ships both a Rust runtime and a TypeScript consumer surface. The TS
side must look and build exactly like the sealant monorepo's existing contract
packages (integration brief §5): `@sealant/runtime-protocol` and
`@sealant/runtime-client`, `"version": "0.0.0"`, `"private": true`,
`"type": "module"`, source-only `exports` (`"./src/index.ts"`, no build step),
`effect` / `@effect/platform` via `catalog:`, internal deps via `workspace:*`,
`oxlint` + `tsgo` scripts. Those conventions live in the monorepo at
`/Users/yiannis/Developer/oss/Selant/sealant-core` (`apps/`, `packages/`,
`pnpm-workspace.yaml`).

The question is where sealantd's source lives now and how it reaches the
monorepo later. The plan recommends a workspace shape (plan §7) split into
`crates/` and `packages/` but explicitly says to "adapt this to the repository
rather than imposing it blindly".

## Decision

Develop sealantd as a **standalone git repository** at
`/Users/yiannis/Developer/oss/Selant/sealantd`, holding:

- `crates/` — the Rust Cargo workspace from plan §7:
  `sealant-protocol`, `sealant-runtime-core`, `sealant-process`, `sealant-pty`,
  `sealant-telemetry`, `sealant-eventlog`, `sealant-fs`, `sealant-network`,
  `sealant-control`, plus the `sealantd` and `sealantctl` binaries.
- `packages/` — `@sealant/runtime-protocol` (schema-derived TS types and the
  closed error-code union) and `@sealant/runtime-client` (the ergonomic SDK whose
  shape is fixed by plan §19: `health()`, `getCapabilities()`, `startExecution()`,
  `exec()`, `openSession()`, `writeStdin()`, `resizePty()`, `signalProcess()`,
  `closeSession()`, `shutdown()`, `events(): AsyncIterable<TelemetryEvent>`).
- `docs/` — `docs/runtime/` (requirements-matrix, architecture, threat-model,
  protocol, validation-plan, known-limitations per plan §6) and `docs/adr/`.

The two `packages/*` directories adopt the monorepo's TS conventions verbatim
(integration brief §5) so they can be **wired into the sealant monorepo later by
workspace link or publish** — added to the monorepo `pnpm-workspace.yaml` and
consumed as `@sealant/runtime-protocol` / `@sealant/runtime-client` — without
restructuring. Because `exports` points at `./src/index.ts` and versions are
`0.0.0`/`private`, a `workspace:*` link from
`/Users/yiannis/Developer/oss/Selant/sealant-core` is a path addition, not a
release event.

## Decision drivers

- The Rust workspace is the unit of churn during the build-up phase and must not
  be entangled with the monorepo's pnpm/turbo graph or CI while crates are stubs.
- The TS packages must be drop-in for the monorepo's Effect-based contracts
  (`packages/api-contracts/src/core-api/workspaces.ts` is the pattern of record).
- A single repo keeps the Rust serde schema source and the generated TS types in
  one place, which ADR-0002 requires for schema generation to be a build-local
  step rather than a cross-repo pipeline.

## Consequences

**Positive**

- The Rust workspace evolves on the stable toolchain with its own Cargo lock and
  CI, decoupled from the monorepo's package manager and pipeline.
- Schema generation (ADR-0002) runs entirely inside this repo: serde structs in
  `crates/sealant-protocol` → schemars JSON Schema → `packages/runtime-protocol`,
  with no cross-repo artifact handoff.
- Later monorepo adoption is a `pnpm-workspace.yaml` link plus a Containerfile
  `COPY sealantd` (integration brief §6, after `buildkit-builder.ts:1060`); no
  source moves.

**Negative**

- Two repos means two CI configs and a deliberate sync point; a protocol change
  is not atomically visible to monorepo consumers until the link/publish step.
- `workspace:*` linking requires the monorepo to either vendor this repo or pull
  it as a sibling checkout; contributors touching both must clone both.
- Drift risk against the monorepo's `catalog:` pins (effect `^3.21.0`,
  `@effect/platform` `^0.96.0`) must be checked manually until the packages are
  linked into the shared catalog.

## Alternatives considered

- **Build inside the `sealant-core` monorepo from the start.** Rejected for now.
  It would couple a stable-toolchain Rust workspace to the monorepo's
  pnpm/turbo/CI graph during the period when every crate is a stub, slowing
  iteration and forcing the Rust build into a TS-first pipeline. The standalone
  repo preserves the option to migrate in later via the same `workspace:*`
  link, so nothing is foreclosed — this is a sequencing choice, not a permanent
  separation (mirrors plan §7's "adapt rather than impose").
