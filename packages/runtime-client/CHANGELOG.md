# @sealant/runtime-client

## 0.13.0

### Minor Changes

- c18aa16: `bindMount { mountPath, subpath }` (ADR-0014): point a bindable mount's path at a subdirectory of
  its root, or unbind with an empty subpath. Boot reads `SEALANT_BINDABLE_MOUNTS` and `SEALANT_BINDS`,
  and `SEALANT_WORKSPACE_SOURCE=standby` makes the working directory itself bindable. The client gains
  `bindMount(mountPath, subpath)`.

### Patch Changes

- Updated dependencies [c18aa16]
  - @sealant/runtime-protocol@0.13.0

## 0.12.0

### Minor Changes

- 633dbcd: Daemon: opt-in mutual-TLS WebSocket control frontend (ADR-0013). `SEALANT_CONTROL_WSS_LISTEN`
  (boot) / `--wss-listen` (bare CLI) serve the unchanged length-prefixed Protobuf control protocol
  over `wss://…/control` beside the Unix socket — rustls with `WebPkiClientVerifier` and no anonymous
  fallback, so no certificate, a foreign CA, or a serverAuth-only certificate fails the handshake
  before any HTTP byte is read. With the new variables absent the daemon behaves exactly as before.

### Patch Changes

- Updated dependencies [633dbcd]
  - @sealant/runtime-protocol@0.12.0

## 0.11.0

### Minor Changes

- 813ee8e: Pipe-mode sessions: `openSession` accepts `mode: SESSION_MODE_PIPE` to start the leader with plain
  stdio pipes and no controlling terminal — for processes that speak a byte protocol over stdio
  (JSON-RPC / NDJSON servers). stdout is the journaled, attachable output with the same reattach and
  tombstone semantics as PTY sessions; stderr is recorded as telemetry only; `writeStdin` feeds stdin;
  `resizePty` is rejected. `SessionSummary.mode` reports the shape and `FeatureMatrix.pipeSessions`
  advertises support. Unspecified `mode` still means PTY.

### Patch Changes

- Updated dependencies [813ee8e]
  - @sealant/runtime-protocol@0.11.0

## 0.10.0

### Minor Changes

- 8c2d31e: Launcher-provided secret environment: `sealantd boot` accepts a new `SEALANT_SECRET_ENV_FILE`
  input — a JSON object (`name → value`) read exactly once at boot. Its entries are injected into the
  harness child environment explicitly (they bypass the daemon's secret-name scrub, override
  same-named passthrough entries, and can never set the boot-owned `HOME`/`USER`/`LOGNAME`/`PATH`),
  and every value seeds the I/O redactor regardless of its name, so a workspace can receive
  `DATABASE_URL`, `STRIPE_API_KEY`, and friends without them ever riding container env, `docker
inspect`, or captured output in the clear. Names are grammar-checked and must not be
  `SEALANT_`-prefixed; a malformed or unreadable file fails boot loudly (parity with dotfiles
  archives). The launcher is expected to remove the file once the workspace reports ready — from then
  on the values live only in daemon memory and child environments. The `configHash` fingerprint
  logged at readiness now covers the sanitized configuration (env keys, never values).

### Patch Changes

- Updated dependencies [8c2d31e]
  - @sealant/runtime-protocol@0.10.0

## 0.9.0

### Minor Changes

- fde1a2a: Runtime dotfiles hardening + caller-provided archives: `sealantd boot` now applies dotfiles BEFORE
  the control socket binds (readiness-gated injections like credential files can no longer race a
  dotfiles apply into `$HOME`), `SEALANT_DOTFILES_REPO_REF` is optional (absent clones the remote's
  default branch instead of assuming `main`), and a new `SEALANT_DOTFILES_ARCHIVE_DIR` input applies
  caller-staged gzipped tars (`manifest.json` + `<n>.tar.gz`, per-archive manager/target/bootstrap)
  through the same chezmoi/stow/copy dispatch — the transport for dotfiles resolved host-side with
  the caller's own ssh identity or scanned from a home directory. Archive apply failures abort boot
  like the repo path.

### Patch Changes

- Updated dependencies [fde1a2a]
  - @sealant/runtime-protocol@0.9.0

## 0.8.0

### Minor Changes

- d195113: Custom-base support: `sealantd boot` accepts `SEALANT_OS_FAMILY=custom` (tool paths fall back to
  `/bin/sh` — the custom-base contract guarantees a POSIX shell and nothing more), and the sealantd
  image now ships a fully static `socat` at `/usr/local/bin/socat` beside the daemon, so workspace
  image builders can `COPY --from` the control-relay dependency into any base instead of depending
  on the base's package manager.
- d195113: `sealantd boot` accepts `SEALANT_OS_FAMILY=ubuntu` (Ubuntu workspace images boot with
  fedora/arch-style tool-path defaults; the glibc loader shim stays Nix-only). The unknown-value
  error now lists `fedora|arch|nix|ubuntu`.

### Patch Changes

- Updated dependencies [d195113]
- Updated dependencies [d195113]
  - @sealant/runtime-protocol@0.8.0

## 0.7.0

### Minor Changes

- 12c9a3f: UDP forwards: `openForward` accepts `protocol: "udp"` and opens a connected
  UDP socket instead of a TCP stream. The channel is already message-framed, so
  one frame is exactly one datagram in both directions — boundaries hold end to
  end. Omitted or `"tcp"` keeps the existing byte-stream behavior; the wire
  field is absent for TCP, so old daemons and clients interoperate unchanged.

### Patch Changes

- 12c9a3f: End interactive terminal attachments when their session leader exits, even if a helper process
  inherited the PTY slave and keeps it open. Sealantd now drains output already written by the leader,
  emits the final stream end immediately, and releases the PTY master instead of making clients wait
  for unrelated helper cleanup.
- Updated dependencies [12c9a3f]
- Updated dependencies [12c9a3f]
  - @sealant/runtime-protocol@0.7.0

## 0.6.2

### Patch Changes

- c211894: End interactive terminal attachments when their session leader exits, even if a helper process
  inherited the PTY slave and keeps it open. Sealantd now drains output already written by the leader,
  emits the final stream end immediately, and releases the PTY master instead of making clients wait
  for unrelated helper cleanup.
- Updated dependencies [c211894]
  - @sealant/runtime-protocol@0.6.2

## 0.6.1

### Patch Changes

- f0a6d8b: Keep platform-injected harness credentials in the harness environment. The boot passthrough scrub
  dropped every env var that looked like a secret — including `CLAUDE_CODE_OAUTH_TOKEN`, `GITHUB_TOKEN`,
  and `GH_TOKEN`, which the control plane injects into the container precisely so the harness can use
  them. Those contract keys now survive the scrub, and injectors can exempt further keys by declaring
  them in `SEALANT_HARNESS_ENV_KEYS` (comma-separated). Consumed `SEALANT_*` keys can never be exempted.
- Updated dependencies [f0a6d8b]
  - @sealant/runtime-protocol@0.6.1

## 0.6.0

### Minor Changes

- ce1ade7: Mount-based workspace provisioning, durable interactive PTY sessions, and default-on file watching.

  - **Protocol**: `AttachSessionArgs.fromSequence` (journal replay before live frames), new
    `signalSession` and `readSessionOutput` commands, `SessionOutput`/`SessionOutputChunk` results,
    and `SessionSummary` lifecycle fields (`state`, `exitCode`, `signal`, `startedAtMicros`, journal
    cursor bounds).
  - **Client**: typed `openSession` / `closeSession` / `resizePty` / `listSessions` /
    `signalSession` / `readSessionOutput`, `attachSession(id, { fromSequence })` for
    reattach-with-scrollback, and buffering of stream frames that arrive ahead of the response
    carrying their channel id (journal replay does this by design).
  - **Daemon**: workspaces can be provisioned from a caller-owned bind mount
    (`SEALANT_WORKSPACE_SOURCE=mount` + operator allowlist `SEALANT_MOUNT_ALLOWED_STORE_ROOTS`) with
    the mounted contents never touched by any lifecycle event; PTY output is redacted and journaled
    to disk per session (replayable from sequence 0, retained across client disconnects and after
    exit); `SEALANT_WATCH_FILESYSTEM` now defaults on, with ignore-pruned per-directory watch
    registration and file events stamped with the active execution id.

### Patch Changes

- Updated dependencies [ce1ade7]
  - @sealant/runtime-protocol@0.6.0

## 0.5.1

### Patch Changes

- 21cf300: Boot clone honors the repository's default branch when no ref is given. `SEALANT_WORKSPACE_REPO_REF` is now optional (missing or empty means "the remote's default branch"): the boot clone only passes `--branch` when a ref was explicitly provided, so a plain `git clone` resolves the remote HEAD. Previously the env var was required and the control plane injected `main`, which broke every repository whose default branch isn't `main` (e.g. `master`) with `fatal: Remote branch main not found in upstream origin`.
- 4d91f06: The orphan reaper can no longer steal a Tokio-owned child's exit status. Spawn paths (exec, sftp bridge) now register their child's pid in an owned-pid set under a shared spawn↔reap lock, and the reaper holds that lock for its whole sweep — closing the race where a fast-exiting child (e.g. `printf`) was reaped as an "adopted orphan" before its ownership was recorded, surfacing as `process.exited` with `exit_code: null` (the intermittent `binary_stdio_roundtrips_binary_unsafe_output_and_shuts_down` CI failure).
- Updated dependencies [21cf300]
- Updated dependencies [4d91f06]
  - @sealant/runtime-protocol@0.5.1

## 0.5.0

### Minor Changes

- f0c4c08: Rename the "sandbox" concept to "workspace" everywhere (breaking, coordinated with the core monorepo — no backwards compatibility).

  - Wire: proto field `sandbox_id` → `workspace_id` (field number 3 unchanged); regenerated `sealant_pb.ts` so the embedded descriptor carries the new field name.
  - Client SDK: `sandboxId` option → `workspaceId`, passing `--workspace-id` to the daemon.
  - Daemon contract: env vars `SEALANT_SANDBOX_*` → `SEALANT_WORKSPACE_*`, CLI flag `--sandbox-id` → `--workspace-id`, container root `/sandbox` → `/workspace`, SSH username prefix `sbx-{id}` → `ws-{id}`.

### Patch Changes

- Updated dependencies [f0c4c08]
  - @sealant/runtime-protocol@0.5.0

## 0.4.1

### Patch Changes

- cbacf43: Update repository metadata for the GitHub org rename: `get-sealant` → `sealant-sh`. The npm
  packages and their APIs are unchanged; this refreshes the `repository` URLs (and the image
  namespace referenced in docs) so npm and registries point at the new org.
- Updated dependencies [cbacf43]
  - @sealant/runtime-protocol@0.4.1

## 0.4.0

### Minor Changes

- c278703: sealantd + SDK: fix the daemon/SDK side of three gateway acceptance blockers (§1)

  - **PTY input routing by session.** The daemon's `WriteStdin` already routes by either `processId` (non-PTY stdin) or `sessionId` (PTY input), but the SDK `writeStdin` only ever set `processId`, so PTY keystrokes could not reach an interactive session. `writeStdin` now accepts `string` (treated as `processId`, backward compatible), `{ processId }`, or `{ sessionId }`, and a new `writeSessionInput(sessionId, data)` convenience targets a PTY session directly. The gateway can now deliver SSH keystrokes to a live session.
  - **Channel half-close.** `Channel.end()` did a full local close, which killed inbound delivery — so `ssh host cmd` with an immediate stdin-EOF destroyed the channel before the daemon's output and `StreamEnd` arrived. `end()` is now a true half-close: it sends our `StreamFrame::End` (outbound EOF) and rejects further `write`/`windowUpdate`, but keeps delivering the daemon's inbound bytes until the remote `StreamEnd`, which resolves `closed` as `remote`. A new `destroy()` performs the full local teardown (resolves `closed` as `local`) for real aborts; the explicit `detachSession`/`closeForward`/`closeSftp` teardown commands and the async-iterator `return()` path use it.
  - **Enable forwarding (decouple from telemetry).** `openForward` (direct-tcpip) was gated behind `Feature::NetworkCollection`, which defaults off, so the gateway's tunnel primitive was denied. Forwarding is a gateway _transport_ primitive — the SSH direct-tcpip substrate — not telemetry capture, and `NetworkCollection` is a kill switch for _observing/recording_ network traffic. We decoupled the two: `openForward` is no longer feature-gated (it carries bytes like session-attach and SFTP, both of which are ungated, and has its own connection-scoped eager teardown). Enabling `NetworkCollection` by default was rejected because it would silently turn on network telemetry capture for every workspace as a side effect of wanting a tunnel.

- c278703: sealantd: eager channel teardown + exec-attach (gateway daemon §1.A)

  - BLOCKER fix — eager channel teardown. Previously, when a control connection dropped, an idle `openForward`/`openSftp` whose upstream never wrote left its outbound (far-end→gateway) pump blocked on `read()` forever — it never called `out_tx.send`, so it never observed the closed outbound queue. That leaked the pump task, the socket FD, and the un-reaped `ForwardRuntime`/`SftpRuntime` map entry per disconnect (idle direct-tcpip forwards are the VSCode-Server steady state, so it accumulated unboundedly). The connection now carries a per-`ChannelId` closer registry (`ConnHandle.closers`); each `openForward`/`openSftp`/`attachSession`/exec-attach registers an eager closer that aborts both pumps **and** removes the runtime map entry. On connection teardown the control server drains and invokes every closer, so nothing leaks. PTY attach uses the same eager path.
  - exec-attach (`exec{attach:true}` → `ProcessAttached{process_id, channel_id}`). A non-PTY process's combined stdout/stderr is now delivered over a backpressured `StreamFrame` channel exactly like §1.A's session attach — raw bytes (no telemetry redaction/coalescing), a single shared per-channel `seq` across stdout+stderr, terminated by `StreamFrame::End{exit_code}` on process exit. The binding is established atomically at spawn so the initial output burst is never lost. The always-on lossy `IoChunk` telemetry tap keeps running in parallel. This is the reliable path VSCode's non-PTY bootstrap reads from.

- c278703: sealantd: gateway daemon Phase 1 — reliable byte-conduit channels over the control socket

  - §0 enabler: `ChannelId`, `StreamFrame`/`StreamPayload`/`StreamEnd`, `ServerMessage::Stream` + `ClientMessage::Stream` (domain + proto + convert; `StreamPayload::Data` carries raw bytes, never through telemetry redaction), `ConnHandle` + `ControlService::handle_on_connection`, and a per-connection `ChannelId`→sink registry with connection-scoped teardown.
  - §1.A: `attachSession`/`detachSession` → a reliable, backpressured per-session PTY output stream (single PTY reader fans out to both the lossy `IoChunk` telemetry and the lossless attach channel), `StreamEnd{exit_code}` on leader exit.
  - §1.B: `openForward`/`closeForward` (direct-tcpip) — `TcpStream::connect` from inside the container, two backpressured pumps, gated behind the `networkCollection` feature (`PolicyDenied` on deny).
  - §1.C: `openSftp`/`closeSftp` — bridges the standalone in-container `sftp-server` stdio over a channel.

- c278703: TS SDK: regenerate off the updated proto + add channel-multiplexing client support (gateway substrate)

  - `@sealant/runtime-protocol`: regenerated the protobuf-es output from `sealant.proto` so the byte-conduit surface is now in the SDK — `StreamFrame`/`StreamWindowUpdate`/`StreamEnd`, `ClientMessage::Stream` + `ServerMessage::Stream`, the channel commands (`attachSession`/`detachSession`/`openForward`/`closeForward`/`openSftp`/`closeSftp`) and their results (`StreamAttached`/`ForwardOpened`/`SftpOpened`/`ProcessAttached`), the `AttachMode` enum, and `ExecArgs.attach`. These new types/enums/schemas are explicitly re-exported from the package index, plus a new `asStream(ServerMessage)` narrower and an `encodeServer(ServerMessage)` codec (symmetric with `encodeClient`/`decodeServer`).
  - `@sealant/runtime-client`: added channel support a multiplexing consumer (the gateway's SSH channels) builds on, with the existing API kept intact. The client now demuxes inbound `ServerMessage::Stream` frames by `channel_id` into per-channel `Channel` sinks (an async-iterable of inbound `Uint8Array` bytes with `write`/`windowUpdate`/`end`/`closed`), and muxes outbound bytes back as `ClientMessage::Stream` frames. New methods: `openChannel(channelId)` (low-level register), `attachSession`/`detachSession`, `openForward`/`closeForward`, `openSftp`/`closeSftp`, and `execAttached` — each opener returns `{ result, channel }`. `StreamEnd` closes only its own channel; a dropped connection fails all open channels.

### Patch Changes

- Updated dependencies [c278703]
  - @sealant/runtime-protocol@0.4.0

## 0.3.0

### Minor Changes

- 87c0094: sealantd: boot PID-1 supervisor subcommand

### Patch Changes

- @sealant/runtime-protocol@0.3.0

## 0.2.0

### Minor Changes

- 2861aaf: add SealantClient.fromStream for non-socket transports

### Patch Changes

- @sealant/runtime-protocol@0.2.0

## 0.1.3

### Patch Changes

- d9a57f8: Validate the release pipeline after renaming the publish environment to `release`. No API or runtime changes.
- Updated dependencies [d9a57f8]
  - @sealant/runtime-protocol@0.1.3
