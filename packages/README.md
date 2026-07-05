# sealantd TypeScript packages

- `@sealant/runtime-protocol` — Protobuf wire codec + length-prefixed framing for the control
  protocol. Loads the schema at runtime from `crates/sealant-protocol/proto/sealant.proto`
  (the single source of truth) via `protobufjs`.
- `@sealant/runtime-client` — `SealantClient`: connect to (or spawn) sealantd over a Unix socket,
  run commands, and stream telemetry events as an async iterable.

The wire format is Protobuf (ADR-0012). Message objects use protobuf.js's shape: camelCase fields,
oneofs as a discriminator (e.g. an `io.chunk` event sets `event.ioChunk`), enums as their proto
string names (e.g. `RUNTIME_STATE_HEALTHY`), and binary fields as `Buffer` (no base64). Helpers
(`isIoChunk`, `isProcessExited`, `chunkBytes`) read that shape.

## Running the e2e

The protobuf runtime (`protobufjs`) is a real dependency now, so install once, then run:

```sh
pnpm install
cargo build -p sealantd
node --test packages/runtime-client/test/e2e.test.ts
```

## Monorepo integration (later)

At integration into `sealant-sh/sealant` these become real `workspace:*` packages. Two follow-ups
(ADR-0010 / ADR-0012): generate typed clients with **Buf** (`buf generate`) instead of runtime
protobuf.js loading, and re-express the surface with **Effect Schema** to match
`@sealant/api-contracts`; `buf generate` also produces SDKs for other languages from the same
`.proto`. The `.proto` is vendored into this package at that point so it is self-contained.
