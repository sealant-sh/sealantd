---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Mount-based workspace provisioning, durable interactive PTY sessions, and default-on file watching.

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
