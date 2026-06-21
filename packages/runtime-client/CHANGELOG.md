# @sealant/runtime-client

## 0.4.0

### Minor Changes

- c278703: sealantd + SDK: fix the daemon/SDK side of three gateway acceptance blockers (§1)

  - **PTY input routing by session.** The daemon's `WriteStdin` already routes by either `processId` (non-PTY stdin) or `sessionId` (PTY input), but the SDK `writeStdin` only ever set `processId`, so PTY keystrokes could not reach an interactive session. `writeStdin` now accepts `string` (treated as `processId`, backward compatible), `{ processId }`, or `{ sessionId }`, and a new `writeSessionInput(sessionId, data)` convenience targets a PTY session directly. The gateway can now deliver SSH keystrokes to a live session.
  - **Channel half-close.** `Channel.end()` did a full local close, which killed inbound delivery — so `ssh host cmd` with an immediate stdin-EOF destroyed the channel before the daemon's output and `StreamEnd` arrived. `end()` is now a true half-close: it sends our `StreamFrame::End` (outbound EOF) and rejects further `write`/`windowUpdate`, but keeps delivering the daemon's inbound bytes until the remote `StreamEnd`, which resolves `closed` as `remote`. A new `destroy()` performs the full local teardown (resolves `closed` as `local`) for real aborts; the explicit `detachSession`/`closeForward`/`closeSftp` teardown commands and the async-iterator `return()` path use it.
  - **Enable forwarding (decouple from telemetry).** `openForward` (direct-tcpip) was gated behind `Feature::NetworkCollection`, which defaults off, so the gateway's tunnel primitive was denied. Forwarding is a gateway _transport_ primitive — the SSH direct-tcpip substrate — not telemetry capture, and `NetworkCollection` is a kill switch for _observing/recording_ network traffic. We decoupled the two: `openForward` is no longer feature-gated (it carries bytes like session-attach and SFTP, both of which are ungated, and has its own connection-scoped eager teardown). Enabling `NetworkCollection` by default was rejected because it would silently turn on network telemetry capture for every sandbox as a side effect of wanting a tunnel.

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
