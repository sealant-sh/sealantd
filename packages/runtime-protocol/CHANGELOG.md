# @sealant/runtime-protocol

## 0.5.0

### Minor Changes

- f0c4c08: Rename the "sandbox" concept to "workspace" everywhere (breaking, coordinated with the core monorepo — no backwards compatibility).

  - Wire: proto field `sandbox_id` → `workspace_id` (field number 3 unchanged); regenerated `sealant_pb.ts` so the embedded descriptor carries the new field name.
  - Client SDK: `sandboxId` option → `workspaceId`, passing `--workspace-id` to the daemon.
  - Daemon contract: env vars `SEALANT_SANDBOX_*` → `SEALANT_WORKSPACE_*`, CLI flag `--sandbox-id` → `--workspace-id`, container root `/sandbox` → `/workspace`, SSH username prefix `sbx-{id}` → `ws-{id}`.

## 0.4.1

### Patch Changes

- cbacf43: Update repository metadata for the GitHub org rename: `get-sealant` → `sealant-sh`. The npm
  packages and their APIs are unchanged; this refreshes the `repository` URLs (and the image
  namespace referenced in docs) so npm and registries point at the new org.

## 0.4.0

### Minor Changes

- c278703: TS SDK: regenerate off the updated proto + add channel-multiplexing client support (gateway substrate)

  - `@sealant/runtime-protocol`: regenerated the protobuf-es output from `sealant.proto` so the byte-conduit surface is now in the SDK — `StreamFrame`/`StreamWindowUpdate`/`StreamEnd`, `ClientMessage::Stream` + `ServerMessage::Stream`, the channel commands (`attachSession`/`detachSession`/`openForward`/`closeForward`/`openSftp`/`closeSftp`) and their results (`StreamAttached`/`ForwardOpened`/`SftpOpened`/`ProcessAttached`), the `AttachMode` enum, and `ExecArgs.attach`. These new types/enums/schemas are explicitly re-exported from the package index, plus a new `asStream(ServerMessage)` narrower and an `encodeServer(ServerMessage)` codec (symmetric with `encodeClient`/`decodeServer`).
  - `@sealant/runtime-client`: added channel support a multiplexing consumer (the gateway's SSH channels) builds on, with the existing API kept intact. The client now demuxes inbound `ServerMessage::Stream` frames by `channel_id` into per-channel `Channel` sinks (an async-iterable of inbound `Uint8Array` bytes with `write`/`windowUpdate`/`end`/`closed`), and muxes outbound bytes back as `ClientMessage::Stream` frames. New methods: `openChannel(channelId)` (low-level register), `attachSession`/`detachSession`, `openForward`/`closeForward`, `openSftp`/`closeSftp`, and `execAttached` — each opener returns `{ result, channel }`. `StreamEnd` closes only its own channel; a dropped connection fails all open channels.

## 0.3.0

## 0.2.0

## 0.1.3

### Patch Changes

- d9a57f8: Validate the release pipeline after renaming the publish environment to `release`. No API or runtime changes.
