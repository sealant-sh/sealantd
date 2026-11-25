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
- `PR_SET_NO_NEW_PRIVS` is set at startup; children cannot escalate via setuid binaries. A
  per-person executor (a root daemon whose capture source carries an owner map naming at least one
  person, Mend's ADR 0016) leaves it
  unset: every person there has passwordless `sudo`, so it is root by design, not a sandbox. A
  `host-vm` workspace's normal boot (`sealantd --vm`) leaves it unset too, whatever the source, so
  guest `sudo` works: the guest kernel is the isolation boundary. Its recovery boot keeps it set,
  owner map or not. Boot logs the posture (`privilege posture: …`), and `runtime.getCapabilities` reports
  `noNewPrivileges`. PID 1 names the guest `workspace` and, on a normal boot, makes `/etc/hosts`
  resolve it, so `sudo` does not warn that it cannot resolve the host.
- `max_processes` / `max_sessions` are enforced; overflow is rejected with `policy-denied`.
- Captured I/O is redacted for configured secret literals and high-confidence token shapes; masked
  spans set `transform.redacted` and increment `redactedEvents`.
- A process started with `secretEnv` (`process.secret-env.v1`) is masked with its own patterns
  too: the daemon's literals plus its secret values. Its output, a session's journal and input,
  the events and the spool hold the values masked; another process that prints the same value is
  recorded as it wrote it. The patterns live until the process's capture readers end, and an
  exited session's tombstone holds none. The exec-attach channel is a live, unrecorded forward
  and carries what the process wrote.

## Deploy (Docker)

```sh
docker buildx build --platform linux/amd64,linux/arm64 -f docker/Dockerfile -t sealantd:latest .
```

The image is a single static binary on `scratch`. Mount the workspace and expose the socket via a
shared volume; run as the same uid as the controlling process so peer validation passes.

## Traces and errors

Off unless the daemon is given a DSN. Then it sends its spans over OTLP and its `error!` events and
panics to Sentry. Without one it builds no exporter, starts no thread and makes no network call.
The daemon reads these settings under a `SEALANT_` prefix, because a workspace image's own
`SENTRY_DSN` belongs to the user's code. Boot consumes them, so they never reach the harness.

| Variable | Meaning |
| --- | --- |
| `SEALANT_SENTRY_DSN` | The Sentry project. Errors go to it, and spans go to its OTLP endpoint (`/api/<project>/integration/otlp/v1/traces`). |
| `SEALANT_SENTRY_ENVIRONMENT` | Default `development`. |
| `SEALANT_SENTRY_RELEASE` | Default: the `SENTRY_RELEASE` the binary was built with (`sealantd@<version>`). |
| `SEALANT_SENTRY_TRACES_SAMPLE_RATE` | The share of new traces kept, default `1`. A caller's sampled flag always wins. |
| `SEALANT_OTEL_EXPORTER_OTLP_ENDPOINT`, `SEALANT_OTEL_EXPORTER_OTLP_HEADERS` | Another collector for spans, in place of the DSN's. |

`--log-level` filters stderr only, so `off` (the TypeScript client's default) still exports.

- **Spans.** Each control request is a `sealantd.control.<method>` span. When the request carries
  `trace` (a W3C `traceparent`), the span is a child of the caller's span. Exec, session open and
  attach have child spans for their stages (`sealantd.process.identity`,
  `sealantd.process.spawn`, `sealantd.session.spawn`, `sealantd.session.journal`,
  `sealantd.session.subscribe`). Spans carry the method, the request id and the error code. They
  never carry arguments, environment or output, and log lines never become span events.
- **Errors.** A request that fails with an internal error is reported once, at the control server.
  A forward's dial and a request whose connection has closed are not reported. Every string in a
  Sentry event is masked with the daemon's secrets and token shapes, and loses URL credentials
  and query strings. Events carry no breadcrumbs, host name or request data, and each one is
  linked to the trace of the span it happened in.
- **Boots.** A boot is one trace. In a container, `sealantd.boot` starts with the process, as a
  child of the launcher's span when `SEALANT_TRACEPARENT` (and `SEALANT_TRACESTATE`) name one.
  Its children are the workspace's provisioning (`sealantd.boot.clone`, `.mount` or `.restore`),
  then `sealantd.boot.healthy`, `.control_ready` and `.harness_started`, each measured from the
  boot's start and carrying `sealant.boot.stage`. A recovery boot ends at `control_ready`. An
  error while the boot is open is linked to its trace.
- **host-vm.** The VM runner and the egress proxy read the contract's plain `SENTRY_DSN`,
  `SENTRY_ENVIRONMENT`, `SENTRY_RELEASE`, `SENTRY_TRACES_SAMPLE_RATE` and `OTEL_EXPORTER_OTLP_*`,
  because only sealant sets their environment. The staged `boot-env.json` (or
  `recovery-env.json`) may carry
  `"telemetry": {"traceparent", "tracestate", "sentryDsn", "environment", "release"}`. The runner
  records `sealantd.vm.launch` under that traceparent, with `setup`, `boot_config` and
  `vmm_started` stages. It passes the guest the staged settings, filled in from its own
  environment, with the launch span as the guest's parent. The guest records `sealantd.vm.boot`
  from PID 1's start, with `disk_layout` and `boot_config` recorded as they ran, then the stages
  above. The runner starts its exporter only after it drops privileges, and the guest only after
  it sets its environment. The proxy's policy, revoke and heartbeat requests are
  `sealantd.proxy.admin.*` spans, under the controller's `traceparent` header when it sends one.
- **Export.** One attempt, no retries. At most 2048 spans wait to be sent, and any past that are
  dropped. Shutdown sends what is queued within about two seconds.

## Shutdown

`SIGTERM`/`SIGINT` (or the `runtime.gracefulShutdown` command) drains: managed processes and PTY
sessions are signalled within the grace window, the final filesystem diff is emitted, the egress
proxy stops, and the spool is flushed before exit.

The grace window is 10 s unless `SEALANT_SHUTDOWN_GRACE_MS` (boot) or `--shutdown-grace-ms`
(`sealantd serve`) sets it. On a capture-store workspace a final capture flush runs first —
both capture classes snapped, everything shipped and registered — and it is not bounded by the
grace window: it returns once nothing is pending, or the lease is fenced. A platform that must
bound it sends `capture.flush {kind: final, deadline_ms}` (`sealantctl capture flush --final
--deadline 15m`) before it signals the daemon, and reads the report's `pending` and
`pending_bytes`.
