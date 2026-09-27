---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Five findings of the third Docker end to end.

- A path longer than `PATH_MAX` no longer stops every capture. An untracked file 4,186 bytes
  below the root failed one `lstat`, which failed every snap for the rest of the session. Every
  filesystem call a snap or a restore makes takes a path of any length (resolved through
  `openat`, a run of components at a time); the paths git cannot reach (a file of 4,096 bytes or
  more, a directory it cannot open) are carried by the workspace class and restored from it, byte
  for byte. One path's metadata error, whatever it is, is that path's alone: an automatic snap
  counts it unreadable and carries its last capture, a final snap fails `unreadable` naming it.
  A directory the watcher cannot watch makes its class poll.
- `capture.status` reports each class's failing snaps: `snaps` (field 26, `CaptureClassSnaps`:
  `class`, `snaps_failed`, `last_snap_error`, `snap_failing_since_unix_ms`). `complete` is false
  (`snapshot-failed`) while any class's last snap failed.
- A final flush asked again after a complete one, with the writers stopped and the watcher having
  seen no change, snaps nothing: it answers in milliseconds and `complete` holds throughout (each
  one walked the dependency tree again for 2.5–3 s, `bulk_building` meanwhile).
- `incomplete_reason` reads `in-progress` while a final flush runs (it read `not-final`).
- Once `complete` is reported, nothing more is captured: the final flush seals the chain with a
  final capture when the newest one is of another kind (a scheduled bulk capture the final small
  snap was staged ahead of), and snaps the small class again after a bulk capture when tracked
  files have hardlinked names in the bulk class, so the final capture records the links.
- A restore that cannot write names the path. `sealantd boot` runs as root (README); a daemon that
  is not root keeps its session journals under `$XDG_STATE_HOME/sealantd` or
  `~/.local/state/sealantd` when `SEALANT_SESSION_JOURNAL_DIR` is unset.
