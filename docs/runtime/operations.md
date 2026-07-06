# sealantd operations

How to build, configure, run, and deploy the daemon. See `architecture.md` for design and
`requirements-matrix.md` for the brief-to-code traceability.

## Build

```sh
cargo build --workspace                 # debug
cargo build --release --bin sealantd    # optimized
scripts/build-release.sh                # static musl binaries -> dist/ (amd64 + arm64)
```

The protobuf compiler is **vendored** at build time (`protoc-bin-vendored`), so no system `protoc`
is required and the runtime binary carries no protobuf dependency. Release builds are statically
linked (musl) and stripped (~2.7 MiB), so they run on `scratch`.

## Run

```sh
sealantd --socket /run/sealantd.sock --workspace /workspace
```

Quick end-to-end demo (starts a daemon, runs a command through it, streams telemetry, shuts down):

```sh
examples/demo.sh
```

### CLI flags

| Flag | Purpose |
|------|---------|
| `--socket <path>` | Unix control socket to listen on (mode `0600`). |
| `--stdio` | Serve one connection over stdin/stdout instead of a socket. |
| `--workspace <dir>` | Repository/workspace root (cwd for execs; filesystem watch root). |
| `--spool-dir <dir>` | Enable the durable telemetry spool (crash-safe at-least-once delivery). |
| `--watch-filesystem` | Baseline snapshot + live watch + final diff of the workspace. |
| `--network-proxy` | Route child egress through the explicit proxy and observe HTTP/CONNECT. |
| `--workspace-id`, `--execution-id` | Correlation identifiers stamped onto telemetry. |
| `--shell <path>` | Default shell for interactive PTY sessions. |
| `--check-config` | Validate config, print a sanitized summary, exit. |
| `--print-capabilities` | Print the capability report (JSON) and exit. |
| `--log-level <filter>` | Tracing filter (`info`, `debug`, `off`, …); diagnostics go to stderr. |

Configuration may also be supplied as a file/env (`RuntimeConfig`); CLI flags override. Secrets in
the config are never logged (`--check-config` redacts them).

## Control protocol

Length-prefixed (4-byte big-endian length + body) **Protobuf** frames (ADR-0012); the schema is
`crates/sealant-protocol/proto/sealant.proto`. Clients: the TypeScript SDK (`packages/`) or
`sealantctl` (debug client that decodes protobuf and prints JSON). `buf generate` produces SDKs for
other languages from the same `.proto`.

## Security posture (plan §18)

- The control socket is `0600` and validated by peer uid (`SO_PEERCRED` on Linux, fail-closed);
  additional uids may be permitted via `allowed_peer_uids`.
- `PR_SET_NO_NEW_PRIVS` is set at startup; children cannot escalate via setuid binaries.
- `max_processes` / `max_sessions` are enforced; overflow is rejected with `policy-denied`.
- Captured I/O is redacted for configured secret literals and high-confidence token shapes; masked
  spans set `transform.redacted` and increment `redactedEvents`.

## Deploy (Docker)

```sh
docker buildx build --platform linux/amd64,linux/arm64 -f docker/Dockerfile -t sealantd:latest .
```

The image is a single static binary on `scratch`. Mount the workspace and expose the socket via a
shared volume; run as the same uid as the controlling process so peer validation passes.

## Shutdown

`SIGTERM`/`SIGINT` (or the `runtime.gracefulShutdown` command) drains: managed processes and PTY
sessions are signalled within the grace window, the final filesystem diff is emitted, the egress
proxy stops, and the spool is flushed before exit.
