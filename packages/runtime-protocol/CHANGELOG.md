# @sealant/runtime-protocol

## 0.5.1

### Patch Changes

- 21cf300: Boot clone honors the repository's default branch when no ref is given. `SEALANT_WORKSPACE_REPO_REF` is now optional (missing or empty means "the remote's default branch"): the boot clone only passes `--branch` when a ref was explicitly provided, so a plain `git clone` resolves the remote HEAD. Previously the env var was required and the control plane injected `main`, which broke every repository whose default branch isn't `main` (e.g. `master`) with `fatal: Remote branch main not found in upstream origin`.
- 4d91f06: The orphan reaper can no longer steal a Tokio-owned child's exit status. Spawn paths (exec, sftp bridge) now register their child's pid in an owned-pid set under a shared spawn↔reap lock, and the reaper holds that lock for its whole sweep — closing the race where a fast-exiting child (e.g. `printf`) was reaped as an "adopted orphan" before its ownership was recorded, surfacing as `process.exited` with `exit_code: null` (the intermittent `binary_stdio_roundtrips_binary_unsafe_output_and_shuts_down` CI failure).

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
