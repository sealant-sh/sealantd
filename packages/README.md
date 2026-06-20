# sealantd TypeScript packages

- `@sealant/runtime-protocol` — wire types + length-prefixed JSON framing for the control protocol.
- `@sealant/runtime-client` — `SealantClient`: connect to (or spawn) sealantd over a Unix socket,
  run commands, and stream telemetry events as an async iterable.

## Running the Phase 1 e2e (no install required)

These packages run on Node 24's native TypeScript type-stripping, so the vertical-slice e2e needs no
`pnpm install`:

```sh
cargo build -p sealantd
node --test packages/runtime-client/test/
```

## Monorepo integration (later)

At integration into `get-sealant/sealant` these become real `workspace:*` packages: imports switch to
`@sealant/runtime-protocol`, types are generated/validated from the Rust schemars JSON Schema
(`cargo run -p sealant-protocol --example dump-schema`) and re-expressed with Effect Schema to match
`@sealant/api-contracts`, and `typecheck` runs under `tsgo` (see `docs/adr/0010-*`).
