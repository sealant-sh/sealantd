# sealantd

The authoritative runtime daemon that runs inside Sealant Linux sandboxes. It records a
trustworthy factual record of an execution — process/PTY lifecycle, binary-safe I/O, filesystem
and network evidence — and exposes it over a versioned, length-prefixed JSON control protocol on a
Unix domain socket, consumed by a TypeScript SDK.

It is **not** a terminal emulator, an image builder, a Kubernetes scheduler, an SSH auth server, or
a semantic LLM engine. See `docs/runtime/known-limitations.md` for honest capability boundaries.

## Layout

```
crates/
  sealant-protocol/      typed commands, events, ids, versions, error codes (schema source of truth)
  sealant-runtime-core/  configuration, state machines, policy, health
  sealant-process/       exec, registry, process groups, pidfds, reaping
  sealant-pty/           PTY allocation, sessions, input/output, resize
  sealant-telemetry/     event bus, sequencing, priority, batching, sinks
  sealant-eventlog/      append-only spool, checksums, recovery, rotation
  sealant-fs/            snapshots, hashing, watcher, coalescing, diffs
  sealant-network/       collectors, DNS, proxy, privileged backends
  sealant-control/       Unix socket, stdio adapter, framing, dispatch
  sealantd/              binary composition and lifecycle
  sealantctl/            debug and integration-test client
packages/
  runtime-protocol/      generated/contract-checked TypeScript types (@sealant/runtime-protocol)
  runtime-client/        ergonomic TypeScript SDK client (@sealant/runtime-client)
docs/
  runtime/               requirements matrix, architecture, threat model, validation plan, limits
  adr/                   architecture decision records
```

## Status

Greenfield. Tracked phase-by-phase against `docs/runtime/requirements-matrix.md` (plan §22).

## Build & validate

```
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p sealant-protocol --example dump-schema   # emit the protocol JSON Schema
```

Target is Linux-first (pidfd, inotify, PTY ctty, namespaces). The dev host may be macOS; Linux-only
behaviors are validated inside docker containers.
